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


## Where the context comes from

Production (+15) and sensitive data (+18) are derived at scan time by `app/services/context.py`, never guessed from names:

| Signal | Source | Provenance shown in the score |
| --- | --- | --- |
| Production | tag `Environment`/`Env`/`Stage`/`Tier` with value `prod`, `production`, `prd` or `live` | `Production asset +15 (tag Environment=prod)` |
| Sensitive data | tag `DataClassification` (`confidential`, `restricted`, `pii`, ...) or a true `contains-pii` flag | `Sensitive data +18 (tag DataClassification=confidential)` |
| Sensitive data | resource type that exists to hold data: Secrets Manager secrets, RDS instances | `Sensitive data +18 (resource type secret)` |

Rules of the model:

- A resource name such as `prod-logs` is not evidence.
- Values already set on the asset are never overwritten.
- Untagged resources get no production/sensitive points. The score is therefore a lower bound for accounts that do not use tagging, and the offline scan reports `context_coverage` (assets, tagged, production, sensitive) so this is visible.
- Tag reads are optional: a missing `s3:GetBucketTagging` or `elasticloadbalancing:DescribeTags` permission yields no tags rather than a failed collector.
- The demo fixture declares its context by hand; that is a demonstration input, not a detection.
