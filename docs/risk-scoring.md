# Risk scoring

The risk calculator converts normalized scanner findings into deterministic scores from 0 to 100.

For each unique finding ID, it adds the configured weight for the finding's severity. The default
weights are 25 for Critical, 10 for High, 5 for Medium, and 1 for Low. Informational findings are
included in the severity distribution but add zero points. Every score is capped at 100:

`score = min(100, sum(severity weight for each unique finding))`

The overall score uses all findings. The AWS and Azure scores apply the identical formula only to
findings for that provider. Input order does not affect any score, and repeated instances of the
same finding ID are counted once. Separate findings remain separate even when they share a rule or
resource. Weights can be changed under `risk.weights` in `config/default.yaml` or supplied directly
as a validated `RiskWeights` object.
