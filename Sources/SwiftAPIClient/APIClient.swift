//
//  APIClient.swift
//  SwiftAPIClient
//

import Foundation
import os

/// A generic API client that can be configured for any REST API.
open class APIClient: @unchecked Sendable {

    // MARK: - Configuration

    public struct Configuration: Sendable {
        public let baseURL: URL
        public let additionalHeaders: [String: String]
        public let paginationPageHeader: String
        public let paginationPageCountHeader: String
        public let responseHandler: any ResponseHandler
        public let dateDecodingStrategy: JSONDecoder.DateDecodingStrategy
        public let tokenRefreshHandler: (any TokenRefreshHandler)?
        public let tokenRefreshThreshold: TimeInterval

        public init(
            baseURL: URL,
            additionalHeaders: [String: String] = [:],
            paginationPageHeader: String = "x-pagination-page",
            paginationPageCountHeader: String = "x-pagination-page-count",
            responseHandler: any ResponseHandler = DefaultResponseHandler(),
            dateDecodingStrategy: JSONDecoder.DateDecodingStrategy = .custom(customDateDecodingStrategy),
            tokenRefreshHandler: (any TokenRefreshHandler)? = nil,
            tokenRefreshThreshold: TimeInterval = 300
        ) {
            self.baseURL = baseURL
            self.additionalHeaders = additionalHeaders
            self.paginationPageHeader = paginationPageHeader
            self.paginationPageCountHeader = paginationPageCountHeader
            self.responseHandler = responseHandler
            self.dateDecodingStrategy = dateDecodingStrategy
            self.tokenRefreshHandler = tokenRefreshHandler
            self.tokenRefreshThreshold = tokenRefreshThreshold
        }
    }

    // MARK: - Properties

    public let configuration: Configuration
    public let session: URLSession

    private let authStorage: (any APIAuthentication)?

    private let authStateLock = NSLock()
    nonisolated(unsafe)
    private var cachedAuthState: AuthenticationState?
    
    private let tokenRefreshLock = NSLock()
    nonisolated(unsafe)
    private var ongoingTokenRefreshTask: Task<Void, Error>?

    internal static let jsonEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static let logger = Logger(subsystem: "SwiftAPIClient", category: "APIClient")

    // MARK: - Lifecycle

    public init(
        configuration: Configuration,
        session: URLSession = URLSession(configuration: .default),
        authStorage: (any APIAuthentication)? = nil
    ) {
        self.configuration = configuration
        self.session = session
        self.authStorage = authStorage
    }

    // MARK: - Authentication

    public var isSignedIn: Bool {
        get {
            authStateLock.lock()
            defer { authStateLock.unlock() }
            return cachedAuthState != nil
        }
    }

    /**
     Gets the current authentication state from the authentication storage, and caches the result to make requests.
     You should call this once shortly after initializing the `APIClient` if you provided an `authStorage`.
     */
    public func refreshCurrentAuthState() async throws(AuthenticationError) {
        guard let authStorage else { throw .noStoredCredentials }
        let currentState = try await authStorage.getCurrentState()
        authStateLock.withLock {
            cachedAuthState = currentState
        }
    }

    /**
     Updates the cached authentication state directly without reading from storage.
     Use this when you've just saved credentials and want to immediately update the cache.
     */
    public func updateCachedAuthState(_ state: AuthenticationState?) {
        authStateLock.withLock {
            cachedAuthState = state
        }
    }

    public func signOut() async {
        guard let authStorage else { return }
        await authStorage.clear()
        authStateLock.withLock {
            cachedAuthState = nil
        }
    }

    /**
     Checks if the current token needs to be refreshed based on expiration time.
     Returns true if the token will expire within the configured threshold.
     */
    private func shouldRefreshToken() -> Bool {
        guard let state = authStateLock.withLock({ cachedAuthState }) else {
            return false
        }

        let timeUntilExpiration = state.expirationDate.timeIntervalSinceNow
        return timeUntilExpiration <= configuration.tokenRefreshThreshold
    }

    /**
     Performs a token refresh using the configured TokenRefreshHandler.
     Updates both the auth storage and cached state with the new tokens.
     Serializes concurrent refresh attempts to prevent duplicate refreshes.
     */
    private func performTokenRefresh() async throws {
        // Atomically check if a refresh is in progress and create/store task if not
        let (refreshTask, isNewTask) = tokenRefreshLock.withLock { () -> (Task<Void, Error>, Bool) in
            // If a refresh is already in progress, return the existing task
            if let existingTask = ongoingTokenRefreshTask {
                Self.logger.info("Token refresh already in progress, waiting...")
                return (existingTask, false)
            }
            
            // Create a new refresh task
            let newTask = Task { @Sendable in
                guard let authStorage,
                      let refreshHandler = configuration.tokenRefreshHandler,
                      let currentState = authStateLock.withLock({ cachedAuthState }) else {
                    throw APIError.unauthorized
                }

                Self.logger.info("Refreshing access token")

                // Call the refresh handler to get new tokens
                let newState = try await refreshHandler.refreshToken(
                    using: currentState.refreshToken,
                    client: self
                )

                // Update storage and cache
                await authStorage.updateState(newState)
                authStateLock.withLock {
                    cachedAuthState = newState
                }

                Self.logger.info("Token refresh successful")
            }
            
            // Store the new task atomically
            ongoingTokenRefreshTask = newTask
            return (newTask, true)
        }
        
        // Execute the task (either existing or newly created)
        defer {
            // Clean up only if we created this task
            if isNewTask {
                tokenRefreshLock.withLock {
                    ongoingTokenRefreshTask = nil
                }
            }
        }
        
        try await refreshTask.value
    }

    // MARK: - Request Building

    public func mutableRequest(
        forPath path: String,
        withQuery query: [String: String] = [:],
        isAuthorized authorized: Bool,
        withHTTPMethod httpMethod: Method,
        body: Encodable? = nil
    ) throws -> URLRequest {
        // Build URL
        guard var components = URLComponents(url: configuration.baseURL, resolvingAgainstBaseURL: false) else {
            throw APIClientError.malformedURL
        }

        // Append path to base URL
        if components.path.hasSuffix("/") {
            components.path += path
        } else {
            components.path += "/" + path
        }

        if query.isEmpty == false {
            var queryItems: [URLQueryItem] = []
            for (key, value) in query {
                queryItems.append(URLQueryItem(name: key, value: value))
            }
            components.queryItems = queryItems
            
            // URLComponents follows RFC 3986 and leaves `+` unencoded, but many
            // servers decode `+` as a space. Re-encode it via percentEncodedQuery.
            if let encoded = components.percentEncodedQuery, encoded.contains("+") {
                components.percentEncodedQuery = encoded.replacingOccurrences(of: "+", with: "%2B")
            }
        }

        guard let url = components.url else { throw APIClientError.malformedURL }

        // Request
        var request = URLRequest(url: url)
        request.httpMethod = httpMethod.rawValue

        // Headers
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        // Add additional headers from configuration
        for (key, value) in configuration.additionalHeaders {
            request.addValue(value, forHTTPHeaderField: key)
        }

        if authorized {
            if let accessToken = cachedAuthState?.accessToken {
                request.addValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            } else {
                throw APIClientError.userNotAuthorized
            }
        }

        // Body
        if let body {
            request.httpBody = try Self.jsonEncoder.encode(body)
        }

        return request
    }

    // MARK: - Error Handling

    private func handleResponse(response: URLResponse?) throws {
        try configuration.responseHandler.handleResponse(response)
    }

    // MARK: - Perform Requests

    /**
     Downloads the contents of a URL based on the specified URL request. Handles ``APIError/retry(after:)`` up to the specified `retryLimit`
     
     - Note: This method can throw any error type defined by your `ResponseHandler`. The automatic retry functionality
             only applies to `APIError.retry(after:)` errors and automatic token refresh for 401 errors.
     */
    public func fetchData(request: URLRequest, retryLimit: Int = 3) async throws -> (Data, URLResponse) {
        var retryCount = 0
        var tokenRefreshAttempted = false
        var currentRequest = request

        while true {
            do {
                let (data, response) = try await session.data(for: currentRequest)
                try handleResponse(response: response)
                return (data, response)
            } catch let error as APIError {
                // Handle APIError retry logic
                switch error {
                case .retry(let retryDelay):
                    retryCount += 1
                    if retryCount >= retryLimit {
                        throw error
                    }
                    Self.logger.info("Retrying after delay: \(retryDelay)")
                    try await Task.sleep(for: .seconds(retryDelay))
                    try Task.checkCancellation()
                case .unauthorized:
                    // Only attempt token refresh for authenticated requests
                    // Unauthenticated requests getting 401 should just fail immediately
                    // This prevents deadlock when refresh handler's request gets 401
                    let isAuthenticatedRequest = currentRequest.value(forHTTPHeaderField: "Authorization") != nil
                    
                    if isAuthenticatedRequest, 
                       !tokenRefreshAttempted, 
                       configuration.tokenRefreshHandler != nil, 
                       authStorage != nil {
                        tokenRefreshAttempted = true
                        Self.logger.info("Received 401, attempting token refresh")
                        do {
                            try await performTokenRefresh()
                            // Update the Authorization header with the new token
                            if let newAccessToken = authStateLock.withLock({ cachedAuthState?.accessToken }) {
                                currentRequest.setValue("Bearer \(newAccessToken)", forHTTPHeaderField: "Authorization")
                            }
                            // Retry the request with the new token
                            continue
                        } catch {
                            Self.logger.error("Token refresh failed: \(error)")
                            throw error
                        }
                    } else {
                        throw error
                    }
                default:
                    throw error
                }
            } catch {
                // For non-APIError types (custom errors from ResponseHandler), throw immediately
                throw error
            }
        }
    }

    /**
     Downloads the contents of a URL based on the specified URL request, and decodes the data into an API object.
     Proactively refreshes tokens if they are about to expire before making the request.
     */
    public func perform<T: Codable & Hashable & Sendable>(request: URLRequest, retryLimit: Int = 3) async throws -> T {
        var finalRequest = request
        
        // Only check for token refresh if this is an authenticated request
        // This prevents deadlock when the refresh handler uses client.perform() for unauthenticated requests
        let isAuthenticatedRequest = request.value(forHTTPHeaderField: "Authorization") != nil
        
        if isAuthenticatedRequest && shouldRefreshToken() {
            Self.logger.info("Token expires soon, proactively refreshing")
            try await performTokenRefresh()
            
            // Update the Authorization header with the new token
            if let newAccessToken = authStateLock.withLock({ cachedAuthState?.accessToken }) {
                finalRequest.setValue("Bearer \(newAccessToken)", forHTTPHeaderField: "Authorization")
            }
        }

        let (data, response) = try await fetchData(request: finalRequest, retryLimit: retryLimit)
        return try decodeObject(from: data, response: response)
    }

    /// Decodes data into an API object. If the object type is `PagedObject` the headers will be extracted from the response.
    private func decodeObject<T: Codable & Hashable & Sendable>(from data: Data, response: URLResponse) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = configuration.dateDecodingStrategy

        if let pagedType = T.self as? PagedObjectProtocol.Type {
            let decodedItems = try decoder.decode(pagedType.objectType, from: data)
            var currentPage = 0
            var pageCount = 0
            if let r = response as? HTTPURLResponse {
                currentPage = Int(r.value(forHTTPHeaderField: configuration.paginationPageHeader) ?? "0") ?? 0
                pageCount = Int(r.value(forHTTPHeaderField: configuration.paginationPageCountHeader) ?? "0") ?? 0
            }
            return pagedType.createPagedObject(with: decodedItems, currentPage: currentPage, pageCount: pageCount) as! T
        }

        return try decoder.decode(T.self, from: data)
    }
}

// MARK: - Errors

public enum APIClientError: Error {
    case malformedURL
    case userNotAuthorized
    case couldNotParseData
}
