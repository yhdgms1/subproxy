pub const BOT_PATTERNS: &[&str] = &[
    // Generic bot / crawler indicators
    "bot",
    "crawler",
    "spider",
    "scraper",
    "preview",
    "unfurl",

    // Messengers & Social media link preview bots
    "telegram",             // TelegramBot
    "discord",              // Discordbot
    "whatsapp",             // WhatsApp preview
    "viber",                // Viber
    "vkshare",              // VKontakte share bot
    "vk.com",               // VK preview bot
    "vk-bot",               // VK robot
    "vkontakte",            // VKontakte
    "odkl",                 // Odnoklassniki (OdklBot)
    "odnoklassniki",        // Odnoklassniki
    "ok.ru",                // ok.ru bot
    "facebookexternalhit",  // Facebook link previewer
    "facebot",              // Facebook crawler
    "meta-externalagent",   // Meta external agent
    "meta-externalfetcher", // Meta fetcher
    "twitter",              // Twitterbot
    "x-bot",                // X bot
    "slack",                // Slackbot, Slack-ImgProxy
    "skypeuripreview",      // Skype URL preview
    "linkedin",             // LinkedInBot
    "linespider",           // LINE spider
    "micromessenger",       // WeChat preview / crawler
    "mpcrawler",            // WeChat crawler
    "applebot",             // Apple iMessage preview / Siri
    "reddit",               // RedditBot
    "pinterest",            // Pinterest
    "snapchat",             // Snapchat URL preview
    "tumblr",               // Tumblr
    "bluesky",              // BlueskyCard
    "mastodon",             // Mastodon
    "pleroma",              // Pleroma
    "misskey",              // Misskey
    "lemmy",                // Lemmy
    "matrix-media-repo",    // Matrix previewer

    // Search engines & major web crawlers
    "googlebot",            // Googlebot
    "google-pagerenderer",  // Google preview
    "google-inspectiontool",// Google inspection
    "feedfetcher-google",   // Google feed fetcher
    "bingbot",              // Bingbot
    "bingpreview",          // Bing preview
    "msnbot",               // MSN bot
    "yandex",               // YandexBot, YandexImages, etc.
    "baiduspider",          // Baidu
    "duckduckbot",          // DuckDuckGo
    "slurp",                // Yahoo Slurp
    "sogou",                // Sogou
    "seznambot",            // Seznam
    "petalbot",             // PetalBot (Huawei)
    "bytespider",           // ByteDance / TikTok
    "tiktok",               // TikTok bot

    // SEO, monitoring & security scanners
    "ahrefs",               // AhrefsBot
    "semrush",              // SemrushBot
    "dotbot",               // Moz DotBot
    "rogerbot",             // Moz RogerBot
    "mj12bot",              // Majestic
    "screaming frog",       // Screaming Frog
    "ia_archiver",          // Internet Archive
    "archive.org",          // Archive.org bot
    "censys",               // Censys
    "shodan",               // Shodan
    "uptimerobot",          // UptimeRobot
    "pingdom",              // Pingdom

    // AI & LLM scrapers
    "gptbot",               // OpenAI GPTBot
    "chatgpt",              // ChatGPT-User
    "oai-searchbot",        // OpenAI SearchBot
    "claude",               // ClaudeBot, Claude-Web
    "anthropic",            // Anthropic AI
    "perplexity",           // Perplexity
    "cohere",               // Cohere AI
    "ccbot",                // Common Crawl
    "amazonbot",            // Amazon Bot
    "diffbot",              // Diffbot
];

/// Returns `true` if the User-Agent is missing, empty, or matches known bot patterns.
/// HTTP libraries (curl, reqwest, python-requests, etc.) are intentionally NOT blocked.
pub fn is_bot(user_agent: Option<&str>) -> bool {
    let ua = match user_agent {
        Some(ua) if !ua.trim().is_empty() => ua.to_ascii_lowercase(),
        _ => return true,
    };

    BOT_PATTERNS.iter().any(|&pattern| ua.contains(pattern))
}
