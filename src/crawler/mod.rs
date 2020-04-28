use async_recursion::async_recursion;
use dns_lookup::lookup_addr;
use reqwest::{Client, ClientBuilder, Url};
use scraper::{ElementRef, Html, Selector};
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;

#[non_exhaustive]
#[derive(Clone)]
pub struct Crawler {
    client: Client,
    bases: HashMap<String, String>,
    pages: HashMap<String, Vec<String>>,
}

impl Crawler {
    pub fn new() -> Crawler {
        let client: Client = ClientBuilder::new()
            .user_agent("FreifunkSearchProjektCrawler")
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let bases_map = HashMap::new();
        let pages_map = HashMap::new();
        Crawler {
            client,
            bases: bases_map,
            pages: pages_map,
        }
    }

    pub async fn start(&mut self, destination: IpAddr, port: u16) {
        println!("Starting crawling of {} on port {}", destination, port);
        println!("Checking if we can get the host of that IP");
        match lookup_addr(&destination) {
            Ok(v) => {
                println!(
                    "Found Hostname: {}; Trying the Hostname as well as the IP",
                    v
                );
                //TODO remove testing
                match self.crawl(format!("nordgedanken.dev:{}", port), None)
                    .await {
                    Ok(_) => {println!("Finished Crawling of nordgedanken.dev:{}", port)},
                    Err(e) => {println!("{}", e)},
                }
                /*
                match self.crawl(format!("nordgedanken.dev:{}", port), None)
                    .await {
                    Ok(_) => {println!("Finished Crawling of {}:{}", destination, port)},
                    Err(e) => {println!("{}", e)},*/
            }
            Err(_) => {
                println!("No Hostname found. Continuing without it.");
                match self.crawl(format!("nordgedanken.dev:{}", port), None)
                    .await {
                    Ok(_) => {println!("Finished Crawling of {}:{}", destination, port)},
                    Err(e) => {println!("{}", e)},
                }
            }
        }
    }

    #[async_recursion(? Send)]
    pub async fn crawl(
        &mut self,
        server: String,
        initial_server: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        println!("Getting: {}", server);
        let splits: Vec<&str> = server.split(':').collect();
        let address = if server.contains("https") || server.contains("http") {
            server.clone()
        } else if (*splits.get(1).unwrap()) == "443" {
            format!("https://{}", server.clone())
        } else {
            format!("http://{}", server.clone())
        };

        let resp = self.client.get(&address).send().await?.text().await?;

        let document = Html::parse_document(&resp);
        let selector = Selector::parse(r#"meta[http-equiv="refresh"][content]"#).unwrap();
        let redirect_nodes: Vec<ElementRef> = document.select(&selector).collect();
        let redirect_node = redirect_nodes.get(0);
        match redirect_node {
            None => {
                println!("NONE");
                self.get_links(
                    server.clone(),
                    document,
                    initial_server.clone().unwrap_or_else(|| server.clone()),
                )
                .await?;
                return Ok(());
            }
            Some(element) => {
                let content = element.value().attr("content");
                let splits: Vec<&str> = content.unwrap().split(';').collect();
                if !splits.is_empty() {
                    for split in splits {
                        if split.to_lowercase().contains("url") {
                            let url_split: Vec<&str> = split.split('=').collect();
                            let redirect_url = url_split.get(1).unwrap();
                            self.crawl((*redirect_url).to_string(), initial_server.clone())
                                .await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn get_base_tag(&mut self, server: String, document: Html) -> Result<(), Box<dyn Error>> {
        let selector = Selector::parse(r#"base[href]"#).unwrap();
        if document.select(&selector).next().is_none() {
            println!("No more links on {}", server);
            return Ok(());
        }
        for element in document.select(&selector) {
            let href = element.value().attr("href").unwrap();
            self.bases.insert(server.clone(), href.to_string());
        }
        Ok(())
    }

    #[async_recursion(? Send)]
    async fn get_links(
        &mut self,
        server: String,
        document: Html,
        initial_server: String,
    ) -> Result<(), Box<dyn Error>> {
        if self.pages.get(initial_server.clone().as_str()).is_none() {
            self.pages.insert(initial_server.clone(), Vec::new());
        }
        let mut pages = self
            .pages
            .get(initial_server.clone().as_str())
            .unwrap()
            .to_vec();
        println!("{:#?}", self.pages);
        let selector = Selector::parse(r#"a[href]"#).unwrap();
        if document.clone().select(&selector).next().is_none() {
            println!("No more links on {}", server);
            return Ok(());
        }
        if !self.bases.contains_key(server.as_str()) {
            self.get_base_tag(server.clone(), document.clone()).await?;
        }
        let base_url = self.bases.get(server.as_str());
        match base_url {
            None => {
                for element in document.clone().select(&selector) {
                    let mut href = element.value().attr("href").unwrap().to_string();
                    // Don't use arguments
                    href = (*href.split('?').collect::<Vec<&str>>().get(0).unwrap()).to_string();
                    if server.clone().contains(&href.clone()) {
                        continue;
                    };
                    if href.starts_with("mailto") || href.starts_with('#') {
                        continue;
                    };
                    let new_address = if href.starts_with("https://") || href.starts_with("http://")
                    {
                        let parsed_initial_server =
                            Url::parse(initial_server.clone().as_str()).unwrap();
                        let parsed_href = Url::parse(href.clone().as_str()).unwrap();
                        if parsed_initial_server.host().unwrap() != parsed_href.host().unwrap() {
                            continue;
                        }
                        href.clone()
                    } else if href.clone().starts_with('/') {
                        [initial_server.clone(), href.clone()].join("")
                    } else {
                        [initial_server.clone(), "/".to_string(), href.clone()].join("")
                    };
                    if pages.clone().contains(&new_address.clone()) {
                        continue;
                    };
                    pages.push(new_address.clone());
                    self.pages.insert(initial_server.clone(), pages.clone());
                    self.crawl(new_address, Some(initial_server.clone()))
                        .await?;
                }
            }
            Some(base_url) => {
                let base_url = base_url.to_owned();
                for element in document.clone().select(&selector) {
                    let mut href = element.value().attr("href").unwrap().to_string();
                    // Don't use arguments
                    href = (*href.split('?').collect::<Vec<&str>>().get(0).unwrap()).to_string();
                    if server.clone().contains(&href.clone()) {
                        continue;
                    };
                    if href.starts_with("mailto") || href.starts_with('#') {
                        continue;
                    };
                    let new_address = if href.starts_with("https://") || href.starts_with("http://")
                    {
                        let parsed_initial_server =
                            Url::parse(initial_server.clone().as_str()).unwrap();
                        let parsed_href = Url::parse(href.clone().as_str()).unwrap();
                        if parsed_initial_server.host().unwrap() != parsed_href.host().unwrap() {
                            continue;
                        }
                        href.clone()
                    } else {
                        handle_base_tag(base_url.clone(), href).await?
                    };
                    if pages.clone().contains(&new_address.clone()) {
                        continue;
                    };
                    pages.push(new_address.clone());
                    self.pages.insert(initial_server.clone(), pages.clone());
                    self.crawl(new_address, Some(initial_server.clone()))
                        .await?;
                }
            }
        }

        Ok(())
    }
}

#[inline]
async fn handle_base_tag(base_url: String, mut url: String) -> Result<String, Box<dyn Error>> {
    let parsed_url = Url::parse(url.as_str()).is_err();
    if parsed_url && !url.starts_with('/') {
        url = [base_url, url].join("");
    }
    Ok(url)
}
