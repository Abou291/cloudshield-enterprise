# Risk engine

The score is additive and capped at 100:

| Factor | Points |
| --- | ---: |
| Low / medium / high / critical technical severity | 8 / 20 / 30 / 40 |
| Internet exposure | 22 |
| Production environment | 15 |
| Sensitive data | 18 |
| Administrative privilege | 15 |
| Detection confidence | 0–10 |

This is not a probability of compromise. It is a prioritization score. The
weights must eventually be calibrated against real analyst decisions and false
positive data.

An additive model was selected because every point has a visible reason and
the model can be reviewed without hidden multiplication effects. A
multiplicative-looking formula is not automatically more scientific.

Each finding stores:

- the final score;
- human-readable reasons;
- machine-readable factors;
- the rule confidence;
- evidence used by the rule.

Changes to weights require regression tests and a documented migration plan if
historical scores must remain comparable.

