use regex::Regex;

pub struct WWWAuth {
    pub realm: String,
    pub params: Vec<(String, String)>,
}

impl WWWAuth {
    pub fn parse(text: &str) -> Self {
        // TODO: lazy static
        let realm_regex = Regex::new(r#"([\w\d\-]+) realm="([.\-\w\d/:]+)"(.+)"#).unwrap();

        let captures = realm_regex.captures(text).unwrap();

        let realm = captures.get(2).unwrap().as_str().to_string();

        let params_text = captures.get(3).unwrap().as_str();
        let params_regex = Regex::new(r#",([\w\d\-]+)="([.\-\w\d/:]+)""#).unwrap();

        let params: Vec<(String, String)> = params_regex
            .captures_iter(params_text)
            .map(|c| {
                (
                    c.get(1).unwrap().as_str().to_string(),
                    c.get(2).unwrap().as_str().to_string(),
                )
            })
            .collect();

        Self { realm, params }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_www_auth_success() {
        let realm = "https://auth.docker.io";
        let www_auth_header = format!(r#"Bearer realm="{}""#, realm);
        let auth = WWWAuth::parse(&www_auth_header);

        assert_eq!(auth.realm, realm);
    }
}
