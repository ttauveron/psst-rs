#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitBucket {
    CreateMinute,
    CreateHour,
    ReadMinute,
}

impl RateLimitBucket {
    pub const fn key_prefix(self) -> &'static str {
        match self {
            Self::CreateMinute => "create-minute",
            Self::CreateHour => "create-hour",
            Self::ReadMinute => "read-minute",
        }
    }

    pub const fn bucket_size_seconds(self) -> i64 {
        match self {
            Self::CreateMinute | Self::ReadMinute => 60,
            Self::CreateHour => 60 * 60,
        }
    }

    pub fn bucket_for_timestamp(self, now_timestamp: i64) -> i64 {
        now_timestamp.div_euclid(self.bucket_size_seconds())
    }

    pub fn key(self, requester_ip_hash: &str) -> String {
        format!("{}:{requester_ip_hash}", self.key_prefix())
    }

    pub fn purge_cutoff_bucket(self, now_timestamp: i64, buckets_to_keep: i64) -> i64 {
        let buckets_to_keep = buckets_to_keep.max(1);
        self.bucket_for_timestamp(now_timestamp)
            .saturating_sub(buckets_to_keep - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimitBucket;

    #[test]
    fn computes_expected_bucket_sizes() {
        assert_eq!(RateLimitBucket::CreateMinute.bucket_size_seconds(), 60);
        assert_eq!(RateLimitBucket::CreateHour.bucket_size_seconds(), 3600);
        assert_eq!(RateLimitBucket::ReadMinute.bucket_size_seconds(), 60);
    }

    #[test]
    fn computes_expected_bucket_numbers() {
        assert_eq!(RateLimitBucket::CreateMinute.bucket_for_timestamp(125), 2);
        assert_eq!(RateLimitBucket::CreateHour.bucket_for_timestamp(7_500), 2);
    }

    #[test]
    fn builds_expected_bucket_keys() {
        assert_eq!(
            RateLimitBucket::CreateMinute.key("ip-hash"),
            "create-minute:ip-hash"
        );
        assert_eq!(
            RateLimitBucket::CreateHour.key("ip-hash"),
            "create-hour:ip-hash"
        );
        assert_eq!(
            RateLimitBucket::ReadMinute.key("ip-hash"),
            "read-minute:ip-hash"
        );
    }

    #[test]
    fn computes_purge_cutoff_bucket_for_retention_window() {
        assert_eq!(RateLimitBucket::CreateMinute.purge_cutoff_bucket(600, 2), 9);
        assert_eq!(RateLimitBucket::CreateHour.purge_cutoff_bucket(7_200, 1), 2);
    }
}
