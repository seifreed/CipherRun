use super::super::{ScannerFormatter, format_advanced_grade};
use crate::http::tester::HeaderAnalysisResult;
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn display_advanced_header_analysis(&self, result: &HeaderAnalysisResult) {
        self.display_hsts_analysis(result);
        self.display_hpkp_analysis(result);
        self.display_cookie_analysis(result);
        self.display_datetime_check(result);
        self.display_banner_detection(result);
        self.display_reverse_proxy_detection(result);
    }

    pub(super) fn display_hsts_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(hsts) = &result.hsts_analysis {
            println!("\n{}", "HSTS Analysis:".cyan());
            let status = if hsts.enabled {
                format!("Y Enabled - {}", hsts.details).green()
            } else {
                format!("X Disabled - {}", hsts.details).red()
            };
            println!("  Status: {}", status);
            println!("  Grade:  {:?}", hsts.grade);
            if hsts.enabled {
                if let Some(max_age) = hsts.max_age {
                    println!(
                        "    max-age:          {} ({} days)",
                        max_age,
                        max_age / 86400
                    );
                }
                println!("    includeSubDomains: {}", hsts.include_subdomains);
                println!("    preload:           {}", hsts.preload);
            }
        }
    }

    pub(super) fn display_hpkp_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(hpkp) = &result.hpkp_analysis
            && hpkp.enabled
        {
            println!("\n{}", "HPKP Analysis:".cyan());
            println!("  {} {}", "!".yellow(), hpkp.details.yellow());
            println!("  Pins: {}", hpkp.pins.len());
        }
    }

    pub(super) fn display_cookie_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(cookies) = &result.cookie_analysis {
            println!("\n{}", "Cookie Security:".cyan());
            println!("  {}", cookies.details);
            println!("  Grade: {:?}", cookies.grade);

            if !cookies.cookies.is_empty() {
                println!("\n  Cookies:");
                for cookie in &cookies.cookies {
                    self.display_single_cookie(cookie);
                }
            }
        }
    }

    pub(super) fn display_single_cookie(&self, cookie: &crate::http::headers_advanced::CookieInfo) {
        let samesite_str = cookie
            .samesite
            .as_ref()
            .map(|s| format!("SameSite={}", s))
            .unwrap_or_default();

        let security_flags = format!(
            "{}{}{}",
            if cookie.secure { "Secure " } else { "" },
            if cookie.httponly { "HttpOnly " } else { "" },
            samesite_str
        );

        let status = if cookie.secure && cookie.httponly && cookie.samesite.is_some() {
            "Y".green()
        } else {
            "!".yellow()
        };

        let flags_display = if security_flags.is_empty() {
            "no security flags".red().to_string()
        } else {
            security_flags
        };

        println!("    {} {} [{}]", status, cookie.name.cyan(), flags_display);
    }

    pub(super) fn display_datetime_check(&self, result: &HeaderAnalysisResult) {
        if let Some(datetime) = &result.datetime_check
            && let Some(server_date) = &datetime.server_date
        {
            println!("\n{}", "Server Time:".cyan());
            let sync_status = if datetime.synchronized {
                "Y Synchronized".green()
            } else {
                "! Out of sync".yellow()
            };
            println!("  {}", sync_status);
            println!("  Server Date: {}", server_date);
            if let Some(skew) = datetime.skew_seconds {
                println!("  Time Skew:   {} seconds", skew);
            }
        }
    }

    pub(super) fn display_banner_detection(&self, result: &HeaderAnalysisResult) {
        if let Some(banners) = &result.banner_detection {
            println!("\n{}", "Server Banners:".cyan());
            let grade_color = format_advanced_grade(&banners.grade);
            println!("  {}", grade_color);

            if let Some(server) = &banners.server {
                println!("  Server:      {}", server);
            }
            if let Some(powered_by) = &banners.powered_by {
                println!("  X-Powered-By: {}", powered_by);
            }
            if let Some(app) = &banners.application {
                println!("  Application:  {}", app);
            }

            if banners.version_exposed {
                println!("  {} Version information exposed", "!".red());
            } else {
                println!("  {} Version information hidden", "Y".green());
            }
        }
    }

    pub(super) fn display_reverse_proxy_detection(&self, result: &HeaderAnalysisResult) {
        if let Some(proxy) = &result.reverse_proxy_detection
            && proxy.detected
        {
            println!("\n{}", "Reverse Proxy:".cyan());
            println!("  {}", proxy.details);
            if let Some(proxy_type) = &proxy.proxy_type {
                println!("  Type: {}", proxy_type.cyan());
            }
            if let Some(via) = &proxy.via_header {
                println!("  Via: {}", via);
            }

            let headers_found = self.collect_proxy_headers(proxy);
            if !headers_found.is_empty() {
                println!("  Headers: {}", headers_found.join(", "));
            }
        }
    }

    pub(super) fn collect_proxy_headers(
        &self,
        proxy: &crate::http::headers_advanced::ReverseProxyDetection,
    ) -> Vec<&'static str> {
        let mut headers = Vec::new();
        if proxy.x_forwarded_for {
            headers.push("X-Forwarded-For");
        }
        if proxy.x_real_ip {
            headers.push("X-Real-IP");
        }
        if proxy.x_forwarded_proto {
            headers.push("X-Forwarded-Proto");
        }
        headers
    }
}
