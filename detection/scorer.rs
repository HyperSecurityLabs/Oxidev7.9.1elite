use strsim::normalized_levenshtein;

/// Bayesian confidence calculator for vulnerability verdicts.
/// Combines multiple signal sources into a single confidence score.
pub struct Scorer;

impl Scorer {
    /// Compute Levenshtein-based similarity between two response bodies.
    /// Returns a value in [0.0, 1.0] where 1.0 = identical.
    pub fn response_similarity(baseline: &str, response: &str) -> f64 {
        if baseline.is_empty() && response.is_empty() {
            return 1.0;
        }
        if baseline.is_empty() || response.is_empty() {
            return 0.0;
        }
        normalized_levenshtein(baseline, response)
    }

    /// Compute how different a response is from baseline as a difference score.
    /// Returns a value in [0.0, 1.0] where 1.0 = completely different.
    pub fn response_diff_score(baseline: &str, response: &str) -> f64 {
        1.0 - Self::response_similarity(baseline, response)
    }

    /// N-gram based cosine similarity for content comparison.
    /// Catches structural changes that Levenshtein might miss on large bodies.
    pub fn ngram_cosine(a: &str, b: &str, n: usize) -> f64 {
        let grams_a = Self::ngrams(a, n);
        let grams_b = Self::ngrams(b, n);
        if grams_a.is_empty() || grams_b.is_empty() {
            return 0.0;
        }
        let dot: usize = grams_a.iter().map(|g| grams_b.iter().filter(|h| *h == g).count()).sum();
        let mag_a = (grams_a.len() as f64).sqrt();
        let mag_b = (grams_b.len() as f64).sqrt();
        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }
        dot as f64 / (mag_a * mag_b)
    }

    fn ngrams(s: &str, n: usize) -> Vec<String> {
        s.chars()
            .collect::<Vec<char>>()
            .windows(n)
            .map(|w| w.iter().collect())
            .collect()
    }

    /// Compute a Bayesian confidence score from raw evidence signals.
    ///
    /// `likelihoods` should be values in [0.0, 1.0] representing the probability
    /// of observing the evidence given a true vulnerability.
    /// `prior` is the prior probability that the class is vulnerable (default 0.1).
    ///
    /// Returns posterior probability in [0.0, 1.0].
    pub fn bayesian_confidence(likelihoods: &[f64], prior: f64) -> f64 {
        if likelihoods.is_empty() {
            return prior;
        }
        let prior = prior.clamp(0.001, 0.999);
        let mut posterior = prior;
        for &likelihood in likelihoods {
            let likelihood = likelihood.clamp(0.001, 0.999);
            // P(V|E) = P(E|V) * P(V) / (P(E|V)*P(V) + P(E|~V)*P(~V))
            // Assume P(E|~V) = 0.1 (false positive rate)
            let false_positive_rate = 0.1;
            let numerator = likelihood * posterior;
            let denominator = numerator + false_positive_rate * (1.0 - posterior);
            if denominator > 0.0 {
                posterior = numerator / denominator;
            }
        }
        posterior
    }

    /// Quick confidence gate: returns true only if confidence passes threshold.
    pub fn passes_threshold(confidence: f64, threshold: f64) -> bool {
        confidence >= threshold
    }

    /// Ensemble confirmation: require at least `required` of `signals` to be true.
    pub fn ensemble_confirm(signals: &[bool], required: usize) -> bool {
        signals.iter().filter(|&&s| s).count() >= required
    }
}
