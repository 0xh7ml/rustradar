# Module Plan: `pkg/runner`

---

## 1. Module Overview & Purpose

The `pkg/runner` module is the central orchestration and coordination engine of Subfinder. It manages:
1. **Configuration & Option Ingestion**: Parsing CLI flags, loading provider API keys from YAML configs and environment variables, and validating configuration parameters.
2. **Domain Batching & Multi-Threading**: Scheduling targets across concurrent worker goroutines bounded by `Options.Threads`.
3. **Enumeration Lifecycle**: Managing the single-domain enumeration workflow, stream deduplication, and wildcard certificate tracking.
4. **Active DNS Coordination**: Initializing the wildcard probe resolution pool and filtering wildcard sinkhole IPs.
5. **Pattern Matching & Suffix Security**: Compiling glob and regular expression filters, ensuring candidate subdomains strictly match the apex target without trailing continuation bypasses.
6. **Thread-Safe Multi-Format Output**: Writing discovered subdomains to STDOUT, text files, per-domain directories, or structured JSONL format with source provenance and IP mapping.
7. **Performance Telemetry**: Aggregating and printing tabular statistics on execution times, requests made, errors encountered, and results returned.

---

## 2. File Structure

```
pkg/runner/
├── banners.go                  # ASCII art banner, version metadata, update check callback
├── config.go                   # YAML provider config creation and deserialization
├── doc.go                      # Go package documentation
├── enumerate.go                # Single-domain enumeration logic, deduplication, wildcard cert merging
├── initialize.go               # Engine initialization (resolver client, agent creation, key injection)
├── options.go                  # CLI flag declarations, Options struct, default rate limits, listSources
├── outputter.go                # Buffered OutputWriter (plain text, JSONL, source attribution, IP mapping)
├── runner.go                   # Runner struct, EnumerateMultipleDomainsWithCtx batch dispatcher
├── stats.go                    # Tabular telemetry printer for per-source metrics
├── util.go                     # Target domain sanitization, scheme stripping, and normalization
├── validate.go                 # Cross-flag validation and regex compilation
├── banners.go                  # ASCII banner and update checking
├── concurrency_test.go         # Concurrency safety & race detection tests
├── concurrency_active_test.go  # Concurrency tests with active DNS resolution
├── config_concurrency_test.go  # Thread-safe config loading tests
├── enumerate_test.go           # Unit tests for domain enumeration
├── filter_test.go              # Unit tests for glob and regex match/filter compilation
└── util_test.go                # Unit tests for domain normalization
```

---

## 3. Core Data Structures & Code Architecture

### 3.1 `Options` Struct ([`pkg/runner/options.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/options.go#L34-L82))

The `Options` struct encapsulates all runtime configurations:

```go
type Options struct {
	Verbose            bool                // Show verbose output per source
	NoColor            bool                // Disable ANSI color output
	JSON               bool                // Format output as JSON Lines (JSONL)
	HostIP             bool                // Write subdomains in host:ip format (-active only)
	Silent             bool                // Suppress banner and info logs
	ListSources        bool                // Display all available sources and exit
	RemoveWildcard     bool                // Active DNS wildcard elimination (-nW / -active)
	CaptureSources     bool                // Include all discovering sources in JSON (-cs)
	Stdin              bool                // Input provided via STDIN pipe
	Version            bool                // Show version and exit
	OnlyRecursive      bool                // Use only sources supporting recursive enumeration
	All                bool                // Enable all sources, including slow search engines
	Statistics         bool                // Output tabular per-source statistics
	Threads            int                 // Concurrent domains and active DNS lookups
	Timeout            int                 // Per-source HTTP timeout (seconds)
	MaxEnumerationTime int                 // Global enumeration timeout (minutes)
	Domain             goflags.StringSlice // Target apex domains
	DomainsFile        string              // Path to text file containing target domains
	Output             io.Writer           // Output stream destination (default: os.Stdout)
	OutputFile         string              // File path to write found subdomains to
	OutputDirectory    string              // Directory to write per-domain results
	Sources            goflags.StringSlice // Specific sources to run exclusively
	ExcludeSources     goflags.StringSlice // Sources to exclude
	Resolvers          goflags.StringSlice // Custom DNS resolvers
	ResolverList       string              // Path to file containing custom DNS resolvers
	Config             string              // Path to config.yaml
	ProviderConfig     string              // Path to provider-config.yaml
	Proxy              string              // HTTP/SOCKS5 proxy URL
	RateLimit          int                 // Global HTTP request rate limit per second
	RateLimits         goflags.RateLimitMap// Granular per-provider rate limits
	ExcludeIps         bool                // Exclude raw IPs from input domain list
	Match              goflags.StringSlice // Glob patterns to match
	Filter             goflags.StringSlice // Glob patterns to filter
	MatchRegex         goflags.StringSlice // Regular expressions to match
	FilterRegex        goflags.StringSlice // Regular expressions to filter
	ResultCallback     OnResultCallback    // Callback triggered on every unique subdomain found
	DisableUpdateCheck bool                // Disable automatic update check
	MaxResults         int                 // Limit results per source (0 = unlimited)
	MaxResponseBodySize int                // Max bytes read from source HTTP bodies (0 = unlimited)
}
```

---

### 3.2 `Runner` Struct ([`pkg/runner/runner.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/runner.go#L30-L41))

The `Runner` orchestrates the execution flow across passive agents, active resolvers, and output writers:

```go
type Runner struct {
	options           *Options
	passiveAgent      *passive.Agent
	resolverClient    *resolve.Resolver
	rateLimit         *subscraping.CustomRateLimit
	newPassiveAgent   func() *passive.Agent
	sharedRateLimiter subscraping.RequestLimiter
	outputMu          *sync.Mutex
	domainOutput      bool
	matchRegexes      []*regexp.Regexp
	filterRegexes     []*regexp.Regexp
}
```

---

### 3.3 Core Implementation: `NewRunner` ([`pkg/runner/runner.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/runner.go#L46-L94))

```go
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()
	runner := &Runner{options: options}
	if err := runner.compileFilters(); err != nil {
		return nil, err
	}

	var providerKeys map[string][]string

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		providerKeys = options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		providerKeys = options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine(providerKeys)

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	// Initialize the custom rate limit
	runner.rateLimit = &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
		CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{
			Map: make(map[string]time.Duration),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
			if sourceRateLimit.Duration > 0 {
				_ = runner.rateLimit.CustomDuration.Set(source, sourceRateLimit.Duration)
			}
		}
	}

	return runner, nil
}
```

---

### 3.4 Multi-Domain Batch Dispatcher: `EnumerateMultipleDomainsWithCtx` ([`pkg/runner/runner.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/runner.go#L139-L276))

Handles concurrent domain processing while enforcing shared batch rate limits:

```go
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) (err error) {
	if r.options.Threads < 0 {
		return errors.New("threads must not be negative")
	}

	workers := max(1, r.options.Threads)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create shared batch rate limiter so provider budgets span across all domain workers
	limiter, err := r.passiveAgent.NewRateLimiter(ctx, r.options.RateLimit, r.rateLimit)
	if err != nil {
		return fmt.Errorf("create batch rate limiter: %w", err)
	}
	defer func() {
		if closeErr := limiter.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close batch rate limiter: %w", closeErr))
		}
	}()

	batch := *r
	options := *r.options
	batch.options = &options
	batch.sharedRateLimiter = limiter
	batch.outputMu = &sync.Mutex{}
	batch.domainOutput = true

	if options.RemoveWildcard {
		batch.resolverClient = r.resolverClient.WithConcurrencyLimit(workers)
	}

	if callback := options.ResultCallback; callback != nil {
		options.ResultCallback = func(entry *resolve.HostEntry) {
			batch.outputMu.Lock()
			defer batch.outputMu.Unlock()
			callback(entry)
		}
	}

	var sharedFile *os.File
	defer func() {
		if sharedFile != nil {
			err = errors.Join(err, sharedFile.Close())
		}
	}()

	jobs := make(chan string)
	var wg sync.WaitGroup
	var firstError error
	var errorOnce sync.Once

	fail := func(err error) {
		errorOnce.Do(func() { firstError = err; cancel() })
	}

	// Spawn domain worker pool
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				if ctx.Err() != nil {
					return
				}

				worker := batch
				worker.passiveAgent = r.newPassiveAgent()

				if _, err := worker.EnumerateSingleDomainWithCtx(ctx, domain, writers); err != nil {
					fail(err)
					return
				}
			}
		}()
	}

	scanner := bufio.NewScanner(reader)
	ip := regexp.MustCompile(`^([0-9\.]+$)`)

scan:
	for ctx.Err() == nil && scanner.Scan() {
		domain := replacer.Replace(preprocessDomain(scanner.Text()))
		if domain == "" || (options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		if options.OutputFile != "" && sharedFile == nil {
			sharedFile, err = NewOutputWriter(options.JSON).createFile(options.OutputFile, true)
			if err != nil {
				fail(err)
				break
			}
			writers = append(append([]io.Writer(nil), writers...), sharedFile)
			batch.domainOutput = false
		} else if options.OutputFile == "" && options.OutputDirectory != "" {
			suffix := ".txt"
			if options.JSON {
				suffix = ".json"
			}

			batch.outputMu.Lock()
			file, openErr := NewOutputWriter(options.JSON).createFile(path.Join(options.OutputDirectory, domain+suffix), true)
			if openErr == nil {
				openErr = file.Close()
			}
			batch.outputMu.Unlock()

			if openErr != nil {
				fail(openErr)
				break
			}
		}

		select {
		case <-ctx.Done():
			break scan
		case jobs <- domain:
		}
	}

	if err := scanner.Err(); err != nil {
		fail(fmt.Errorf("read domains: %w", err))
	}

	close(jobs)
	wg.Wait()

	if firstError != nil {
		return firstError
	}
	return ctx.Err()
}
```

---

### 3.5 Single Domain Enumerator: `EnumerateSingleDomainWithCtx` ([`pkg/runner/enumerate.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/enumerate.go#L38-L138))

```go
func (r *Runner) EnumerateSingleDomainWithCtx(ctx context.Context, domain string, writers []io.Writer) (map[string]map[string]struct{}, error) {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Initialize active wildcard resolution pool if requested
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPoolWithCtx(ctx, max(1, r.options.Threads), r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	// Trigger passive enumeration across all selected sources
	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomainsWithCtx(
		ctx, domain, r.options.Proxy, r.options.RateLimit, r.options.Timeout,
		time.Duration(r.options.MaxEnumerationTime)*time.Minute,
		passive.WithCustomRateLimit(r.rateLimit),
		passive.WithMaxResults(r.options.MaxResults),
		passive.WithMaxResponseBodySize(int64(r.options.MaxResponseBodySize)),
		passive.WithRateLimiter(r.sharedRateLimiter),
	)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	uniqueMap := make(map[string]resolve.HostEntry)
	sourceMap := make(map[string]map[string]struct{})
	skippedCounts := make(map[string]int)

	go func() {
		for result := range passiveResults {
			if ctx.Err() != nil {
				continue
			}

			switch result.Type {
			case subscraping.Error:
				gologger.Warning().Msgf("Encountered an error with source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				value := normalizeSubdomain(result.Value)
				subdomain := replacer.Replace(value)
				isWildcard := strings.Contains(value, "*."+subdomain)

				// Suffix validation ensures candidate belongs to the target domain
				if !strings.HasSuffix(subdomain, "."+domain) {
					skippedCounts[result.Source]++
					continue
				}

				if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
					if _, ok := uniqueMap[subdomain]; !ok {
						sourceMap[subdomain] = make(map[string]struct{})
					}

					if _, ok := sourceMap[subdomain][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(subdomain)
					}
					sourceMap[subdomain][result.Source] = struct{}{}

					// Deduplicate
					if _, ok := uniqueMap[subdomain]; ok {
						skippedCounts[result.Source]++
						if !uniqueMap[subdomain].WildcardCertificate && isWildcard {
							val := uniqueMap[subdomain]
							val.WildcardCertificate = true
							uniqueMap[subdomain] = val
						}
						continue
					}

					hostEntry := resolve.HostEntry{Domain: domain, Host: subdomain, Source: result.Source, WildcardCertificate: isWildcard}
					if r.options.ResultCallback != nil && !r.options.RemoveWildcard {
						r.options.ResultCallback(&hostEntry)
					}

					uniqueMap[subdomain] = hostEntry

					// Dispatch to active DNS queue if wildcard elimination is enabled
					if r.options.RemoveWildcard {
						select {
						case resolutionPool.Tasks <- hostEntry:
						case <-ctx.Done():
						}
					}
				}
			}
		}

		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// Read resolved results from active pool
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
					if r.options.ResultCallback != nil {
						r.options.ResultCallback(&resolve.HostEntry{Domain: domain, Host: result.Host, Source: result.Source, WildcardCertificate: result.WildcardCertificate})
					}
				}
			}
		}
	}

	wg.Wait()
	// Output results to writers...
	return sourceMap, nil
}
```

---

### 3.6 Domain Sanitization & Normalization Helpers ([`pkg/runner/util.go`](file:///home/pwnbox/Desktop/code_projects/sectools/subfinder/pkg/runner/util.go#L25-L49))

```go
func preprocessDomain(s string) string {
	s = stringsutil.NormalizeWithOptions(s,
		stringsutil.NormalizeOptions{
			StripComments: true,
			TrimCutset:    "\n\t\"'` ",
			Lowercase:     true,
		},
	)
	// Strip a leading http(s):// scheme and any path/query/fragment
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	return s
}

func normalizeSubdomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}
```

---

## 4. Working Process Summary

1. `ParseOptions()` parses CLI switches and loads configurations.
2. `NewRunner()` configures filters, injects API keys, and instantiates the passive engine and DNS resolver.
3. `RunEnumeration()` selects input modes (`-d`, `-dL`, or STDIN).
4. `EnumerateMultipleDomainsWithCtx()` creates a shared cross-domain batch rate limiter and launches domain worker goroutines.
5. `EnumerateSingleDomainWithCtx()` probes for DNS wildcards (if `-nW`), spawns 54 passive scrapers, validates suffixes, deduplicates candidates, resolves hosts, and streams results to thread-safe output writers.
