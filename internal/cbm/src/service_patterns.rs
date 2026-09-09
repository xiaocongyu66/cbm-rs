//! service_patterns.rs — 1:1 rewrite of `internal/cbm/service_patterns.c`:
//! classify call edges by library identity in the RESOLVED qualified name.
//!
//! Instead of matching callee names (ambiguous: "get", "post", "send"),
//! match library identifiers in the resolved QN — the QN contains the full
//! module path, so import aliases are transparent:
//!   r.get("/api") → QN `project.venv.requests.api.get` → "requests" → HTTP
//!
//! Two-level matching: (1) library identifier in QN determines the edge
//! type, (2) method suffix determines the HTTP method. Matching is
//! case-sensitive; library names are specific enough that substring
//! matching is safe. Route registration is checked FIRST — this prevents
//! gin/echo from matching as HTTP clients (both have .get/.post suffixes).

use std::cell::RefCell;
use std::collections::HashMap;

/// Service edge kind (C cbm_svc_kind_t; discriminants match the C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SvcKind {
    #[default]
    None = 0,
    /// Synchronous HTTP client call.
    Http = 1,
    /// Async dispatch (message broker, task queue).
    Async = 2,
    /// Config/env accessor.
    Config = 3,
    /// Route registration (router.GET, app.get, Route::post).
    RouteReg = 4,
    /// gRPC client call (protobuf stub invocation).
    Grpc = 5,
    /// GraphQL client query/mutation.
    Graphql = 6,
    /// tRPC client procedure call.
    Trpc = 7,
}

/// Library identifier pattern (C lib_pattern_t): a substring to find in the
/// resolved QN; `broker` is the async broker name.
type LibPattern = (&'static str, SvcKind, Option<&'static str>);

const HTTP_LIBRARIES: &[LibPattern] = &[
    // Python
    ("requests", SvcKind::Http, None),
    ("httpx", SvcKind::Http, None),
    ("aiohttp", SvcKind::Http, None),
    ("urllib", SvcKind::Http, None),
    ("urllib3", SvcKind::Http, None),
    ("httplib2", SvcKind::Http, None),
    ("pycurl", SvcKind::Http, None),
    ("treq", SvcKind::Http, None),
    ("uplink", SvcKind::Http, None),
    // JavaScript / TypeScript
    ("axios", SvcKind::Http, None),
    ("superagent", SvcKind::Http, None),
    ("needle", SvcKind::Http, None),
    ("node-fetch", SvcKind::Http, None),
    ("undici", SvcKind::Http, None),
    ("ofetch", SvcKind::Http, None),
    ("wretch", SvcKind::Http, None),
    ("sindresorhus/ky", SvcKind::Http, None),
    ("phin", SvcKind::Http, None),
    // Go
    ("net/http", SvcKind::Http, None),
    ("resty", SvcKind::Http, None),
    ("sling", SvcKind::Http, None),
    ("heimdall", SvcKind::Http, None),
    ("gentleman", SvcKind::Http, None),
    ("retryablehttp", SvcKind::Http, None),
    // Java / Kotlin
    ("HttpClient", SvcKind::Http, None),
    ("OkHttp", SvcKind::Http, None),
    ("okhttp3", SvcKind::Http, None),
    ("RestTemplate", SvcKind::Http, None),
    ("WebClient", SvcKind::Http, None),
    ("Unirest", SvcKind::Http, None),
    ("AsyncHttpClient", SvcKind::Http, None),
    ("apache.http", SvcKind::Http, None),
    ("Retrofit", SvcKind::Http, None),
    ("Feign", SvcKind::Http, None),
    ("ktor.client", SvcKind::Http, None),
    ("kittinunf.fuel", SvcKind::Http, None),
    // Rust
    ("reqwest", SvcKind::Http, None),
    ("hyper", SvcKind::Http, None),
    ("surf", SvcKind::Http, None),
    ("ureq", SvcKind::Http, None),
    ("isahc", SvcKind::Http, None),
    ("attohttpc", SvcKind::Http, None),
    // C#
    ("HttpClient", SvcKind::Http, None),
    ("RestSharp", SvcKind::Http, None),
    ("Flurl", SvcKind::Http, None),
    ("Refit", SvcKind::Http, None),
    // Ruby
    ("HTTParty", SvcKind::Http, None),
    ("Faraday", SvcKind::Http, None),
    ("RestClient", SvcKind::Http, None),
    ("Typhoeus", SvcKind::Http, None),
    ("Excon", SvcKind::Http, None),
    ("Net::HTTP", SvcKind::Http, None),
    // PHP
    ("Guzzle", SvcKind::Http, None),
    ("guzzle", SvcKind::Http, None),
    ("curl", SvcKind::Http, None),
    ("Symfony\\HttpClient", SvcKind::Http, None),
    // C/C++
    ("cpr", SvcKind::Http, None),
    ("cpp-httplib", SvcKind::Http, None),
    ("Poco.Net", SvcKind::Http, None),
    ("Beast", SvcKind::Http, None),
    // Swift
    ("Alamofire", SvcKind::Http, None),
    ("Moya", SvcKind::Http, None),
    ("URLSession", SvcKind::Http, None),
    // Dart
    ("Dio", SvcKind::Http, None),
    ("dio", SvcKind::Http, None),
    ("package:http", SvcKind::Http, None),
    ("Chopper", SvcKind::Http, None),
    // Elixir
    ("HTTPoison", SvcKind::Http, None),
    ("Tesla", SvcKind::Http, None),
    ("Finch", SvcKind::Http, None),
    ("Mint.HTTP", SvcKind::Http, None),
    // Scala
    ("sttp", SvcKind::Http, None),
    ("akka.http", SvcKind::Http, None),
    ("http4s", SvcKind::Http, None),
    ("scalaj", SvcKind::Http, None),
    // Haskell
    ("wreq", SvcKind::Http, None),
    ("http-client", SvcKind::Http, None),
    ("http-conduit", SvcKind::Http, None),
    ("servant-client", SvcKind::Http, None),
    ("Network.HTTP", SvcKind::Http, None),
    // Lua
    ("socket.http", SvcKind::Http, None),
    ("resty.http", SvcKind::Http, None),
];

const ASYNC_LIBRARIES: &[LibPattern] = &[
    ("cloudtasks", SvcKind::Async, Some("cloud_tasks")),
    ("cloud_tasks", SvcKind::Async, Some("cloud_tasks")),
    ("cloud.tasks", SvcKind::Async, Some("cloud_tasks")),
    ("CloudTasks", SvcKind::Async, Some("cloud_tasks")),
    ("pubsub", SvcKind::Async, Some("pubsub")),
    ("cloud.pubsub", SvcKind::Async, Some("pubsub")),
    ("PubSub", SvcKind::Async, Some("pubsub")),
    ("aws-sdk-go/service/sqs", SvcKind::Async, Some("sqs")),
    ("aws-sdk-go.service.sqs", SvcKind::Async, Some("sqs")),
    ("aws_sdk_sqs", SvcKind::Async, Some("sqs")),
    ("Amazon.SQS", SvcKind::Async, Some("sqs")),
    ("@aws-sdk/client-sqs", SvcKind::Async, Some("sqs")),
    ("boto3.client.sqs", SvcKind::Async, Some("sqs")),
    ("aws-sdk-go/service/sns", SvcKind::Async, Some("sns")),
    ("aws-sdk-go.service.sns", SvcKind::Async, Some("sns")),
    ("aws_sdk_sns", SvcKind::Async, Some("sns")),
    ("Amazon.SNS", SvcKind::Async, Some("sns")),
    ("@aws-sdk/client-sns", SvcKind::Async, Some("sns")),
    ("eventbridge", SvcKind::Async, Some("eventbridge")),
    ("EventBridge", SvcKind::Async, Some("eventbridge")),
    ("aws-sdk-go/service/lambda", SvcKind::Async, Some("lambda")),
    ("aws-sdk-go.service.lambda", SvcKind::Async, Some("lambda")),
    ("aws_sdk_lambda", SvcKind::Async, Some("lambda")),
    ("@aws-sdk/client-lambda", SvcKind::Async, Some("lambda")),
    ("stepfunctions", SvcKind::Async, Some("stepfunctions")),
    ("ServiceBus", SvcKind::Async, Some("servicebus")),
    ("Azure.Messaging", SvcKind::Async, Some("servicebus")),
    ("kafka", SvcKind::Async, Some("kafka")),
    ("Kafka", SvcKind::Async, Some("kafka")),
    ("kafkajs", SvcKind::Async, Some("kafka")),
    ("sarama", SvcKind::Async, Some("kafka")),
    ("rdkafka", SvcKind::Async, Some("kafka")),
    ("confluent", SvcKind::Async, Some("kafka")),
    ("Confluent.Kafka", SvcKind::Async, Some("kafka")),
    ("amqp", SvcKind::Async, Some("rabbitmq")),
    ("AMQP", SvcKind::Async, Some("rabbitmq")),
    ("amqplib", SvcKind::Async, Some("rabbitmq")),
    ("RabbitMQ", SvcKind::Async, Some("rabbitmq")),
    ("lapin", SvcKind::Async, Some("rabbitmq")),
    ("MassTransit", SvcKind::Async, Some("rabbitmq")),
    ("nats", SvcKind::Async, Some("nats")),
    ("NATS", SvcKind::Async, Some("nats")),
    ("ioredis", SvcKind::Async, Some("redis")),
    ("celery", SvcKind::Async, Some("celery")),
    ("Celery", SvcKind::Async, Some("celery")),
    ("dramatiq", SvcKind::Async, Some("dramatiq")),
    ("huey", SvcKind::Async, Some("huey")),
    ("python-rq", SvcKind::Async, Some("rq")),
    ("rq.Queue", SvcKind::Async, Some("rq")),
    ("bullmq", SvcKind::Async, Some("bullmq")),
    ("BullMQ", SvcKind::Async, Some("bullmq")),
    ("bull.Queue", SvcKind::Async, Some("bull")),
    ("Sidekiq", SvcKind::Async, Some("sidekiq")),
    ("sidekiq", SvcKind::Async, Some("sidekiq")),
    ("Resque", SvcKind::Async, Some("resque")),
    ("GoodJob", SvcKind::Async, Some("goodjob")),
    ("DelayedJob", SvcKind::Async, Some("delayed_job")),
    ("Hangfire", SvcKind::Async, Some("hangfire")),
    ("NServiceBus", SvcKind::Async, Some("nservicebus")),
    ("asynq", SvcKind::Async, Some("asynq")),
    ("RichardKnop/machinery", SvcKind::Async, Some("machinery")),
    ("temporalio", SvcKind::Async, Some("temporal")),
    ("@temporalio", SvcKind::Async, Some("temporal")),
    ("temporal.client", SvcKind::Async, Some("temporal")),
    ("temporal.worker", SvcKind::Async, Some("temporal")),
    ("inngest", SvcKind::Async, Some("inngest")),
    ("Oban", SvcKind::Async, Some("oban")),
    ("Broadway", SvcKind::Async, Some("broadway")),
    ("GenStage", SvcKind::Async, Some("genstage")),
    ("Phoenix.PubSub", SvcKind::Async, Some("phoenix_pubsub")),
    ("Alpakka", SvcKind::Async, Some("alpakka")),
    ("mqtt", SvcKind::Async, Some("mqtt")),
    ("paho.mqtt", SvcKind::Async, Some("mqtt")),
    ("MQTTClient", SvcKind::Async, Some("mqtt")),
    ("mosquitto", SvcKind::Async, Some("mqtt")),
    ("asyncio_mqtt", SvcKind::Async, Some("mqtt")),
    ("gmqtt", SvcKind::Async, Some("mqtt")),
    ("rumqttc", SvcKind::Async, Some("mqtt")),
    ("nats.go", SvcKind::Async, Some("nats")),
    ("nats-py", SvcKind::Async, Some("nats")),
    ("nats.ws", SvcKind::Async, Some("nats")),
    ("nats.java", SvcKind::Async, Some("nats")),
    ("nats.net", SvcKind::Async, Some("nats")),
    ("async-nats", SvcKind::Async, Some("nats")),
    ("nats.rs", SvcKind::Async, Some("nats")),
    ("dapr.clients.grpc", SvcKind::Async, Some("dapr")),
    ("DaprClient", SvcKind::Async, Some("dapr")),
];

const CONFIG_LIBRARIES: &[LibPattern] = &[
    ("getenv", SvcKind::Config, None),
    ("Getenv", SvcKind::Config, None),
    ("getEnv", SvcKind::Config, None),
    ("LookupEnv", SvcKind::Config, None),
    ("lookupEnv", SvcKind::Config, None),
    ("get_env", SvcKind::Config, None),
    ("fetch_env", SvcKind::Config, None),
    ("GetEnvironmentVariable", SvcKind::Config, None),
    ("getProperty", SvcKind::Config, None),
    ("getEnvironment", SvcKind::Config, None),
    ("viper", SvcKind::Config, None),
    ("envconfig", SvcKind::Config, None),
    ("godotenv", SvcKind::Config, None),
    ("decouple", SvcKind::Config, None),
    ("dynaconf", SvcKind::Config, None),
    ("dotenv", SvcKind::Config, None),
    ("nconf", SvcKind::Config, None),
    ("convict", SvcKind::Config, None),
    ("envalid", SvcKind::Config, None),
    ("dotenvy", SvcKind::Config, None),
    ("figment", SvcKind::Config, None),
    ("config-rs", SvcKind::Config, None),
    ("ConfigFactory", SvcKind::Config, None),
    ("ConfigurationProperties", SvcKind::Config, None),
    ("Application.get_env", SvcKind::Config, None),
    ("Application.fetch_env", SvcKind::Config, None),
];

const ROUTE_REG_LIBRARIES: &[LibPattern] = &[
    ("gin-gonic/gin", SvcKind::RouteReg, None),
    ("gin.", SvcKind::RouteReg, None),
    ("go-chi/chi", SvcKind::RouteReg, None),
    ("chi.", SvcKind::RouteReg, None),
    ("gorilla/mux", SvcKind::RouteReg, None),
    ("labstack/echo", SvcKind::RouteReg, None),
    ("echo.", SvcKind::RouteReg, None),
    ("gofiber/fiber", SvcKind::RouteReg, None),
    ("fiber.", SvcKind::RouteReg, None),
    ("net/http.ServeMux", SvcKind::RouteReg, None),
    ("http.ServeMux", SvcKind::RouteReg, None),
    ("httprouter", SvcKind::RouteReg, None),
    ("express", SvcKind::RouteReg, None),
    ("fastify", SvcKind::RouteReg, None),
    ("koa-router", SvcKind::RouteReg, None),
    ("hono", SvcKind::RouteReg, None),
    ("hapi", SvcKind::RouteReg, None),
    ("flask", SvcKind::RouteReg, None),
    ("FastAPI", SvcKind::RouteReg, None),
    ("starlette", SvcKind::RouteReg, None),
    ("Laravel", SvcKind::RouteReg, None),
    ("Illuminate.Routing", SvcKind::RouteReg, None),
    ("Symfony.Routing", SvcKind::RouteReg, None),
    ("ktor.server", SvcKind::RouteReg, None),
    ("ktor.routing", SvcKind::RouteReg, None),
    ("actix-web", SvcKind::RouteReg, None),
    ("actix_web", SvcKind::RouteReg, None),
    ("axum", SvcKind::RouteReg, None),
    ("rocket", SvcKind::RouteReg, None),
    ("Spring", SvcKind::RouteReg, None),
    ("jakarta.ws.rs", SvcKind::RouteReg, None),
    ("Microsoft.AspNetCore", SvcKind::RouteReg, None),
    ("MapGet", SvcKind::RouteReg, None),
    ("MapPost", SvcKind::RouteReg, None),
    ("ActionDispatch", SvcKind::RouteReg, None),
    ("Sinatra", SvcKind::RouteReg, None),
    ("Phoenix.Router", SvcKind::RouteReg, None),
    ("akka.http.scaladsl.server", SvcKind::RouteReg, None),
    ("play.api.routing", SvcKind::RouteReg, None),
];

const GRPC_LIBRARIES: &[LibPattern] = &[
    ("google.golang.org/grpc", SvcKind::Grpc, None),
    ("grpc.Dial", SvcKind::Grpc, None),
    ("grpc.NewClient", SvcKind::Grpc, None),
    ("grpc.DialContext", SvcKind::Grpc, None),
    ("grpc.insecure_channel", SvcKind::Grpc, None),
    ("grpc.secure_channel", SvcKind::Grpc, None),
    ("grpcio", SvcKind::Grpc, None),
    ("grpc.aio", SvcKind::Grpc, None),
    ("io.grpc", SvcKind::Grpc, None),
    ("ManagedChannelBuilder", SvcKind::Grpc, None),
    ("ManagedChannel", SvcKind::Grpc, None),
    ("newBlockingStub", SvcKind::Grpc, None),
    ("newFutureStub", SvcKind::Grpc, None),
    ("Grpc.Net.Client", SvcKind::Grpc, None),
    ("GrpcChannel", SvcKind::Grpc, None),
    ("Grpc.Core", SvcKind::Grpc, None),
    ("@grpc/grpc-js", SvcKind::Grpc, None),
    ("grpc-web", SvcKind::Grpc, None),
    ("tonic", SvcKind::Grpc, None),
    ("package:grpc", SvcKind::Grpc, None),
];

const GRAPHQL_LIBRARIES: &[LibPattern] = &[
    // JS/TS
    ("graphql-request", SvcKind::Graphql, None),
    ("@apollo/client", SvcKind::Graphql, None),
    ("apollo-client", SvcKind::Graphql, None),
    ("urql", SvcKind::Graphql, None),
    ("graphql-tag", SvcKind::Graphql, None),
    // Python
    ("gql", SvcKind::Graphql, None),
    ("sgqlc", SvcKind::Graphql, None),
    ("graphene", SvcKind::Graphql, None),
    // Java
    ("graphql-java", SvcKind::Graphql, None),
    ("DgsQueryExecutor", SvcKind::Graphql, None),
    // Go
    ("graphql-go", SvcKind::Graphql, None),
    ("gqlgen", SvcKind::Graphql, None),
    // Ruby
    ("graphql-ruby", SvcKind::Graphql, None),
    // Rust
    ("async-graphql", SvcKind::Graphql, None),
    ("juniper", SvcKind::Graphql, None),
];

const TRPC_LIBRARIES: &[LibPattern] = &[
    ("@trpc/server", SvcKind::Trpc, None),
    ("@trpc/client", SvcKind::Trpc, None),
    ("@trpc/react-query", SvcKind::Trpc, None),
    ("createTRPCRouter", SvcKind::Trpc, None),
    ("createTRPCProxyClient", SvcKind::Trpc, None),
];

/// Route registration method suffixes (C route_reg_suffixes) — matched on
/// the callee name. (suffix, method); "ANY" for method-agnostic handlers.
const ROUTE_REG_SUFFIXES: &[(&str, &str)] = &[
    (".GET", "GET"),
    (".Get", "GET"),
    (".get", "GET"),
    (".POST", "POST"),
    (".Post", "POST"),
    (".post", "POST"),
    (".PUT", "PUT"),
    (".Put", "PUT"),
    (".put", "PUT"),
    (".DELETE", "DELETE"),
    (".Delete", "DELETE"),
    (".delete", "DELETE"),
    (".PATCH", "PATCH"),
    (".Patch", "PATCH"),
    (".patch", "PATCH"),
    // Handle/HandleFunc (Go stdlib, gorilla)
    (".Handle", "ANY"),
    (".HandleFunc", "ANY"),
    (".handle", "ANY"),
    // Framework-specific route registration
    (".Route", "ANY"),
    (".route", "ANY"),
    ("::get", "GET"),
    ("::post", "POST"),
    ("::put", "PUT"),
    ("::delete", "DELETE"),
    ("::patch", "PATCH"),
    // Minimal API (C# ASP.NET)
    (".MapGet", "GET"),
    (".MapPost", "POST"),
    (".MapPut", "PUT"),
    (".MapDelete", "DELETE"),
    // Router mounting / prefix registration (any method)
    (".include_router", "ANY"),
    (".mount", "ANY"),
    (".add_url_rule", "ANY"),
    (".register_blueprint", "ANY"),
    (".use", "ANY"),
    (".register", "ANY"),
    (".add_route", "ANY"),
    (".add_api_route", "ANY"),
    (".add_api_websocket_route", "ANY"),
];

/// HTTP method inference suffixes (C method_suffixes). `None` method means
/// "suffix recognized but no method" (SendAsync).
const METHOD_SUFFIXES: &[(&str, Option<&str>)] = &[
    (".get", Some("GET")),
    (".Get", Some("GET")),
    (".GET", Some("GET")),
    (".post", Some("POST")),
    (".Post", Some("POST")),
    (".POST", Some("POST")),
    (".put", Some("PUT")),
    (".Put", Some("PUT")),
    (".PUT", Some("PUT")),
    (".delete", Some("DELETE")),
    (".Delete", Some("DELETE")),
    (".DELETE", Some("DELETE")),
    (".patch", Some("PATCH")),
    (".Patch", Some("PATCH")),
    (".PATCH", Some("PATCH")),
    (".head", Some("HEAD")),
    (".Head", Some("HEAD")),
    (".HEAD", Some("HEAD")),
    (".options", Some("OPTIONS")),
    (".Options", Some("OPTIONS")),
    ("GetAsync", Some("GET")),
    ("PostAsync", Some("POST")),
    ("PutAsync", Some("PUT")),
    ("DeleteAsync", Some("DELETE")),
    ("SendAsync", None),
    ("getForObject", Some("GET")),
    ("getForEntity", Some("GET")),
    ("postForObject", Some("POST")),
    ("postForEntity", Some("POST")),
];

// ── Matching implementation ─────────────────────────────────────

/// First library whose identifier appears as a substring in the QN
/// (C match_qn). Case-sensitive.
fn match_qn<'a>(qn: &str, patterns: &'a [LibPattern]) -> Option<&'a LibPattern> {
    if qn.is_empty() {
        return None;
    }
    patterns.iter().find(|p| qn.contains(p.0))
}

/// Does `path` start with `/segment` or `/segment/...`?
fn starts_with_segment(path: &str, segment: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    match rest.strip_prefix(segment) {
        Some(after) => after.is_empty() || after.starts_with('/'),
        None => false,
    }
}

/// Does `path` contain a `/segment` or `/segment/...` component?
fn contains_segment(path: &str, segment: &str) -> bool {
    path.split_inclusive('/').any(|part| {
        let Some(rest) = part.strip_prefix('/') else {
            return false;
        };
        match rest.strip_prefix(segment) {
            Some(after) => after.is_empty() || after.starts_with('/'),
            None => false,
        }
    })
}

fn has_http_route_marker(path: &str) -> bool {
    for seg in ["api", "apis", "graphql", "health", "metrics"] {
        if starts_with_segment(path, seg) {
            return true;
        }
    }
    // /v<digit>... marker.
    let b = path.as_bytes();
    b.len() > 2
        && b[0] == b'/'
        && b[1] == b'v'
        && b[2].is_ascii_digit()
        && (b.len() == 3 || b[3] == b'/')
}

fn has_filesystem_root(path: &str) -> bool {
    const ROOTS: &[&str] = &[
        "etc", "root", "var", "usr", "home", "tmp", "private", "opt", "bin", "sbin", "dev", "proc",
        "sys", "run", "lib", "lib64", "mnt", "media", "boot", "srv", "Users", "Volumes",
    ];
    ROOTS.iter().any(|r| starts_with_segment(path, r))
}

fn has_hidden_config_segment(path: &str) -> bool {
    const SEGMENTS: &[&str] = &[
        ".aws", ".azure", ".config", ".docker", ".env", ".git", ".gnupg", ".kube", ".ssh",
    ];
    SEGMENTS.iter().any(|s| contains_segment(path, s))
}

fn has_filesystem_extension(path: &str) -> bool {
    // Extension = last dot segment before ? or #.
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let Some(last_slash) = path[..end].rfind('/') else {
        return false;
    };
    let Some(dot) = path[last_slash + 1..end]
        .rfind('.')
        .map(|d| last_slash + 1 + d)
    else {
        return false;
    };
    if dot == end - 1 {
        return false; // trailing dot, no extension
    }
    let ext = &path[dot..end];
    const HARD_FILE_EXTS: &[&str] = &[
        ".cfg",
        ".conf",
        ".credentials",
        ".crt",
        ".db",
        ".env",
        ".ini",
        ".key",
        ".pem",
        ".pid",
        ".properties",
        ".service",
        ".sock",
        ".socket",
        ".sqlite",
        ".toml",
    ];
    if HARD_FILE_EXTS.contains(&ext) {
        return true;
    }
    matches!(ext, ".json" | ".yaml" | ".yml" | ".xml") && !has_http_route_marker(path)
}

fn callee_is_delimiter_or_filesystem_builder(callee_name: &str) -> bool {
    // C: method = after last '.' if non-empty, else after last '::' if
    // non-empty, else the whole name.
    let mut method = callee_name;
    if let Some(dot) = callee_name.rfind('.') {
        if !callee_name[dot + 1..].is_empty() {
            method = &callee_name[dot + 1..];
        }
    }
    if let Some(colon) = callee_name.find("::") {
        if !callee_name[colon + 2..].is_empty() {
            method = &callee_name[colon + 2..];
        }
    }
    matches!(
        method,
        "split"
            | "rsplit"
            | "partition"
            | "join"
            | "replace"
            | "replaceAll"
            | "match"
            | "matchAll"
            | "search"
            | "test"
            | "exec"
    ) || callee_name.contains("os.path.join")
        || callee_name.contains("path.join")
}

/// Strip whitespace and one pair of quotes (C strip_string_delimiters).
/// None when the literal is empty or overflows the C's 1024-byte buffer.
fn strip_string_delimiters(literal: &str) -> Option<&str> {
    if literal.is_empty() {
        return None;
    }
    let s = literal.trim_matches([' ', '\t', '\n', '\r']);
    let s = s.strip_prefix(['"', '\'', '`']).unwrap_or(s);
    let s = s.strip_suffix(['"', '\'', '`']).unwrap_or(s);
    if s.is_empty() || s.len() >= 1024 {
        return None;
    }
    Some(s)
}

/// Is this string literal an HTTP route path? (C
/// cbm_service_pattern_is_http_route_literal): accepts "http(s)://..." and
/// non-filesystem "/..." paths; rejects other schemes, filesystem roots,
/// hidden config segments, and file extensions.
pub fn service_pattern_is_http_route_literal(literal: &str, callee_name: &str) -> bool {
    let Some(path) = strip_string_delimiters(literal) else {
        return false;
    };
    if path.is_empty() {
        return false;
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return true;
    }
    if path.contains("://") {
        return false;
    }
    if !path.starts_with('/') {
        return false;
    }
    if callee_is_delimiter_or_filesystem_builder(callee_name) {
        return false;
    }
    if has_filesystem_root(path)
        || has_hidden_config_segment(path)
        || has_filesystem_extension(path)
    {
        return false;
    }
    true
}

// ── TLS result cache ────────────────────────────────────────────

// Per-worker cache of match results (C _svc_cache). The hot path invokes
// pattern matching for EVERY resolved call — 6 pattern-list scans × ~30
// patterns per call — and the same QN repeats hundreds of thousands of
// times; a cache turns the linear scan into one lookup after the first
// miss for that QN. Lifetime is per-worker for the parallel resolve phase.
thread_local! {
    static SVC_CACHE: RefCell<Option<HashMap<String, SvcKind>>> = const { RefCell::new(None) };
}

/// Begin caching match results (C cbm_service_pattern_cache_begin,
/// idempotent).
pub fn service_pattern_cache_begin() {
    SVC_CACHE.with(|c| {
        let mut g = c.borrow_mut();
        if g.is_none() {
            *g = Some(HashMap::new());
        }
    });
}

/// End the cache lifetime (C cbm_service_pattern_cache_end).
pub fn service_pattern_cache_end() {
    SVC_CACHE.with(|c| {
        *c.borrow_mut() = None;
    });
}

/// Is the callee a bare global `fetch` call (C
/// cbm_service_pattern_is_global_fetch)?
pub fn service_pattern_is_global_fetch(callee_name: &str) -> bool {
    callee_name == "fetch"
}

/// Classify a resolved QN (C cbm_service_pattern_match). Route
/// registration is checked first — prevents gin/echo from matching as HTTP
/// clients.
pub fn service_pattern_match(resolved_qn: &str) -> SvcKind {
    if resolved_qn.is_empty() {
        return SvcKind::None;
    }
    if let Some(cached) = SVC_CACHE.with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|m| m.get(resolved_qn).copied())
    }) {
        return cached;
    }

    let result = if let Some((_, kind, _)) = ROUTE_REG_LIBRARIES
        .iter()
        .find(|p| resolved_qn.contains(p.0))
    {
        *kind
    } else if let Some((_, kind, _)) = HTTP_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0)) {
        *kind
    } else if let Some((_, kind, _)) = ASYNC_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0)) {
        *kind
    } else if let Some((_, kind, _)) = CONFIG_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0)) {
        *kind
    } else if let Some((_, kind, _)) = GRPC_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0)) {
        *kind
    } else if let Some((_, kind, _)) = GRAPHQL_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0))
    {
        *kind
    } else if let Some((_, kind, _)) = TRPC_LIBRARIES.iter().find(|p| resolved_qn.contains(p.0)) {
        *kind
    } else {
        SvcKind::None
    };

    SVC_CACHE.with(|c| {
        if let Some(map) = c.borrow_mut().as_mut() {
            map.insert(resolved_qn.to_string(), result);
        }
    });
    result
}

/// HTTP method from a function/method name suffix (C
/// cbm_service_pattern_http_method). None when no suffix matches or the
/// matched suffix carries no method (SendAsync).
pub fn service_pattern_http_method(callee_name: &str) -> Option<&'static str> {
    METHOD_SUFFIXES
        .iter()
        .find(|(suffix, _)| callee_name.ends_with(suffix))
        .and_then(|(_, method)| *method)
}

/// Route registration method from a callee name suffix (C
/// cbm_service_pattern_route_method).
pub fn service_pattern_route_method(callee_name: &str) -> Option<&'static str> {
    ROUTE_REG_SUFFIXES
        .iter()
        .find(|(suffix, _)| callee_name.ends_with(suffix))
        .map(|(_, method)| *method)
}

/// The async broker for a resolved QN (C cbm_service_pattern_broker).
pub fn service_pattern_broker(resolved_qn: &str) -> Option<&'static str> {
    match_qn(resolved_qn, ASYNC_LIBRARIES).and_then(|p| p.2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qn_match_classifies_libraries() {
        assert_eq!(
            service_pattern_match("project.venv.requests.api.get"),
            SvcKind::Http
        );
        assert_eq!(
            service_pattern_match("app.services.celery.tasks.run"),
            SvcKind::Async
        );
        assert_eq!(
            service_pattern_match("google.protobuf.grpc.Dial"),
            SvcKind::Grpc
        );
        assert_eq!(service_pattern_match("os.getenv"), SvcKind::Config);
        assert_eq!(service_pattern_match("plain.local.func"), SvcKind::None);
        assert_eq!(service_pattern_match(""), SvcKind::None);
        // Case-sensitive: "Requests" ≠ "requests".
        assert_eq!(service_pattern_match("project.Requests.get"), SvcKind::None);
    }

    #[test]
    fn route_reg_wins_over_http() {
        // gin QN must classify as ROUTE_REG, not HTTP (gin uses .get/.post).
        assert_eq!(
            service_pattern_match("github.com/gin-gonic/gin.(*Router).GET"),
            SvcKind::RouteReg
        );
        assert_eq!(
            service_pattern_match("github.com.labstack.echo.(*Echo).GET"),
            SvcKind::RouteReg
        );
    }

    #[test]
    fn broker_extracted() {
        assert_eq!(
            service_pattern_broker("tasks.celery.app.send"),
            Some("celery")
        );
        assert_eq!(
            service_pattern_broker("io.confluent.kafka.produce"),
            Some("kafka")
        );
        assert_eq!(service_pattern_broker("kafkajs.client"), Some("kafka"));
        assert_eq!(service_pattern_broker("requests.get"), None);
    }

    #[test]
    fn method_suffix_inference() {
        assert_eq!(service_pattern_http_method("api.get"), Some("GET"));
        assert_eq!(
            service_pattern_http_method("client.PostAsync"),
            Some("POST")
        );
        assert_eq!(service_pattern_http_method("svc.SendAsync"), None);
        assert_eq!(service_pattern_http_method("template.head"), Some("HEAD"));
        assert_eq!(service_pattern_http_method("unrelated"), None);
    }

    #[test]
    fn route_method_inference() {
        assert_eq!(service_pattern_route_method("router.get"), Some("GET"));
        assert_eq!(service_pattern_route_method("app.HandleFunc"), Some("ANY"));
        assert_eq!(service_pattern_route_method("app.MapPost"), Some("POST"));
        assert_eq!(service_pattern_route_method("Route::post"), Some("POST"));
        assert_eq!(service_pattern_route_method("unrelated"), None);
    }

    #[test]
    fn global_fetch() {
        assert!(service_pattern_is_global_fetch("fetch"));
        assert!(!service_pattern_is_global_fetch("window.fetch"));
        assert!(!service_pattern_is_global_fetch(""));
    }

    #[test]
    fn http_route_literals() {
        assert!(service_pattern_is_http_route_literal("/api/users", "r.get"));
        assert!(service_pattern_is_http_route_literal(
            "https://api.example.com/x",
            "r.get"
        ));
        assert!(service_pattern_is_http_route_literal("'/v1/items'", "get"));
        // Filesystem paths rejected.
        assert!(!service_pattern_is_http_route_literal(
            "/etc/passwd",
            "open"
        ));
        assert!(!service_pattern_is_http_route_literal(
            "/home/user/.ssh/id_rsa",
            "read"
        ));
        assert!(!service_pattern_is_http_route_literal(
            "/var/log/app.log",
            "open"
        ));
        // Other scheme rejected.
        assert!(!service_pattern_is_http_route_literal(
            "ftp://host/file",
            "get"
        ));
        // Relative path rejected.
        assert!(!service_pattern_is_http_route_literal(
            "relative/path",
            "get"
        ));
        // os.path.join callers rejected.
        assert!(!service_pattern_is_http_route_literal(
            "/data/config",
            "os.path.join"
        ));
        // .json without a route marker rejected; with one accepted.
        assert!(!service_pattern_is_http_route_literal(
            "/config/app.json",
            "read_json"
        ));
        assert!(service_pattern_is_http_route_literal(
            "/api/config.json",
            "read_json"
        ));
    }

    #[test]
    fn cache_roundtrip_consistent() {
        service_pattern_cache_begin();
        let a = service_pattern_match("x.y.requests.get");
        let b = service_pattern_match("x.y.requests.get");
        service_pattern_cache_end();
        assert_eq!(a, b);
        // After end, cache cleared but result identical.
        assert_eq!(service_pattern_match("x.y.requests.get"), a);
    }
}
