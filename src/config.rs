use interchange::InterchangeType;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub interchange: InterchangeType,
}

impl Default for Config {
    fn default() -> Self {
        Config { interchange: InterchangeType::Json }
    }
}
