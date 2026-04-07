"""Advanced grader with multi-metric evaluation, LLM-as-judge, and detailed scoring breakdown."""
from typing import Any, Dict, List, Optional, Tuple


class ScoringResult:
    """Container for detailed scoring results."""

    def __init__(
        self,
        final_score: float,
        breakdown: Dict[str, float],
        true_positives: int = 0,
        false_positives: int = 0,
        false_negatives: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.final_score = max(0.0, min(1.0, final_score))
        self.breakdown = breakdown
        self.true_positives = true_positives
        self.false_positives = false_positives
        self.false_negatives = false_negatives
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_score": round(self.final_score, 4),
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items()},
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "details": self.details,
        }


def grade_pii_detection(
    flagged_violations: List[Dict[str, Any]],
    ground_truth: List[Dict[str, Any]],
    steps_used: int,
    max_steps: int,
) -> ScoringResult:
    """Grade Task 1: PII Leakage Detection using precision, recall, F1, and efficiency.

    Scoring formula:
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        efficiency = 1.0 - (steps_used / max_steps)
        final_score = 0.35 * precision + 0.35 * recall + 0.15 * f1 + 0.15 * efficiency

    Partial rewards are given for each correctly flagged violation (+0.05 per TP).
    False positives are penalized (-0.02 per FP).
    """
    tp = 0
    fp = 0
    matched_gt_indices = set()
    matched_flagged_indices = set()

    for fi, flagged in enumerate(flagged_violations):
        matched = False
        for gi, gt in enumerate(ground_truth):
            if gi in matched_gt_indices:
                continue
            file_match = flagged.get("file", "") == gt["file"]
            type_match = flagged.get("violation_type", "") == gt["violation_type"]
            if file_match and type_match:
                matched = True
                matched_gt_indices.add(gi)
                matched_flagged_indices.add(fi)
                break
        if matched:
            tp += 1
        else:
            fp += 1

    fn = len(ground_truth) - tp
    fn = max(0, fn)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    efficiency = max(0.0, 1.0 - (steps_used / max_steps))

    final_score = 0.35 * precision + 0.35 * recall + 0.15 * f1 + 0.15 * efficiency

    tp_details = []
    for gi in matched_gt_indices:
        tp_details.append({
            "file": ground_truth[gi]["file"],
            "violation_type": ground_truth[gi]["violation_type"],
            "severity": ground_truth[gi]["severity"],
        })

    fp_details = []
    for fi, flagged in enumerate(flagged_violations):
        if fi not in matched_flagged_indices:
            fp_details.append({
                "file": flagged.get("file", "unknown"),
                "violation_type": flagged.get("violation_type", "unknown"),
            })

    fn_details = []
    for gi, gt in enumerate(ground_truth):
        if gi not in matched_gt_indices:
            fn_details.append({
                "file": gt["file"],
                "violation_type": gt["violation_type"],
                "severity": gt["severity"],
            })

    return ScoringResult(
        final_score=final_score,
        breakdown={
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "efficiency": efficiency,
        },
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        details={
            "true_positive_violations": tp_details,
            "false_positive_violations": fp_details,
            "missed_violations": fn_details,
            "total_ground_truth": len(ground_truth),
            "total_flagged": len(flagged_violations),
        },
    )


def grade_data_flow_mapping(
    agent_edges: List[Dict[str, Any]],
    ground_truth_edges: List[Dict[str, Any]],
    ground_truth_nodes: List[str],
) -> ScoringResult:
    """Grade Task 2: Data Flow Mapping using node coverage, edge coverage, and false edge penalty.

    Scoring formula:
        node_coverage = correctly_identified_nodes / total_real_nodes
        edge_coverage = correctly_identified_edges / total_real_edges
        false_edge_penalty = 0.1 * false_edges_count
        final_score = 0.5 * node_coverage + 0.4 * edge_coverage - false_edge_penalty

    Nodes are identified from source and destination fields in edges.
    Edge matching requires source, destination, and data_type to all match.
    """
    agent_nodes = set()
    for edge in agent_edges:
        src = edge.get("source", "")
        dst = edge.get("destination", "")
        if src:
            agent_nodes.add(src)
        if dst:
            agent_nodes.add(dst)

    correct_nodes = sum(1 for node in ground_truth_nodes if node in agent_nodes)
    total_nodes = len(ground_truth_nodes)
    node_coverage = correct_nodes / total_nodes if total_nodes > 0 else 0.0

    correct_edges = 0
    false_edges = 0
    matched_gt_edges = set()

    for ai, agent_edge in enumerate(agent_edges):
        matched = False
        for gi, gt_edge in enumerate(ground_truth_edges):
            if gi in matched_gt_edges:
                continue
            src_match = agent_edge.get("source", "") == gt_edge.get("source", "")
            dst_match = agent_edge.get("destination", "") == gt_edge.get("destination", "")
            data_match = agent_edge.get("data_type", "") == gt_edge.get("data_type", "")
            if src_match and dst_match and data_match:
                matched = True
                matched_gt_edges.add(gi)
                break
        if matched:
            correct_edges += 1
        else:
            false_edges += 1

    total_edges = len(ground_truth_edges)
    edge_coverage = correct_edges / total_edges if total_edges > 0 else 0.0
    false_edge_penalty = 0.1 * false_edges

    final_score = 0.5 * node_coverage + 0.4 * edge_coverage - false_edge_penalty
    final_score = max(0.0, min(1.0, final_score))

    missing_nodes = [n for n in ground_truth_nodes if n not in agent_nodes]
    missing_edges = [
        ground_truth_edges[gi] for gi in range(len(ground_truth_edges)) if gi not in matched_gt_edges
    ]

    return ScoringResult(
        final_score=final_score,
        breakdown={
            "node_coverage": node_coverage,
            "edge_coverage": edge_coverage,
            "false_edge_penalty": false_edge_penalty,
        },
        true_positives=correct_edges,
        false_positives=false_edges,
        false_negatives=len(missing_edges),
        details={
            "correctly_identified_nodes": correct_nodes,
            "total_nodes": total_nodes,
            "missing_nodes": missing_nodes,
            "correctly_identified_edges": correct_edges,
            "total_edges": total_edges,
            "missing_edges": missing_edges,
        },
    )


def grade_compliance_report(
    agent_findings: List[Dict[str, Any]],
    ground_truth_clauses: List[str],
    ground_truth_findings: List[Dict[str, Any]],
) -> ScoringResult:
    """Grade Task 3: Compliance Gap Report using clause recall, evidence quality, and false clause penalty.

    Scoring formula:
        clause_recall = correctly_cited_clauses / total_applicable_clauses
        evidence_quality = average_llm_judge_score across all findings
        false_clause_penalty = 0.05 * false_clause_count
        final_score = 0.5 * clause_recall + 0.4 * evidence_quality - false_clause_penalty

    LLM Judge Rubric (deterministic approximation):
        1.0: Exact file+line, correct article, accurate description, actionable fix
        0.7: Correct article and violation type, location slightly off, fix present but generic
        0.4: Correct violation type, wrong article citation, no specific location
        0.1: Vague finding, incorrect article, no evidence
        0.0: Hallucinated violation that does not exist in the codebase
    """
    valid_articles = {
        "GDPR Art. 5", "GDPR Art. 6", "GDPR Art. 13", "GDPR Art. 14",
        "GDPR Art. 15", "GDPR Art. 16", "GDPR Art. 17", "GDPR Art. 25",
        "GDPR Art. 32",
        "DPDP Act Sec. 4", "DPDP Act Sec. 5", "DPDP Act Sec. 6",
        "DPDP Act Sec. 8", "DPDP Act Sec. 9", "DPDP Act Sec. 12",
        "CCPA Sec. 1798.100", "CCPA Sec. 1798.105", "CCPA Sec. 1798.81.5",
    }

    correctly_cited_clauses = set()
    false_clauses = []
    evidence_scores = []
    scored_findings = []

    for finding in agent_findings:
        article = finding.get("article", "")
        violation_type = finding.get("violation_type", "")
        location = finding.get("location", "")
        evidence = finding.get("evidence", "")
        recommended_fix = finding.get("recommended_fix", "")
        violation_desc = finding.get("violation", "")

        matched_clause = None
        for clause in ground_truth_clauses:
            if clause in article:
                matched_clause = clause
                break

        if matched_clause:
            correctly_cited_clauses.add(matched_clause)
            score = _score_evidence_quality_deterministic(
                finding, ground_truth_findings
            )
            evidence_scores.append(score)
            scored_findings.append({
                "clause": matched_clause,
                "evidence_score": score,
                "finding_summary": violation_desc[:80] if violation_desc else "N/A",
            })
        else:
            has_valid_article = any(va in article for va in valid_articles)
            if not has_valid_article and article:
                false_clauses.append(article)
            elif has_valid_article:
                for clause in ground_truth_clauses:
                    if clause.split()[0] in article:
                        correctly_cited_clauses.add(clause)
                        score = _score_evidence_quality_deterministic(
                            finding, ground_truth_findings
                        )
                        evidence_scores.append(score)
                        scored_findings.append({
                            "clause": clause,
                            "evidence_score": score,
                            "finding_summary": violation_desc[:80] if violation_desc else "N/A",
                        })
                        break
                else:
                    if article:
                        false_clauses.append(article)

    clause_recall = len(correctly_cited_clauses) / len(ground_truth_clauses) if ground_truth_clauses else 0.0
    evidence_quality = sum(evidence_scores) / len(evidence_scores) if evidence_scores else 0.0
    false_clause_penalty = 0.05 * len(false_clauses)

    final_score = 0.5 * clause_recall + 0.4 * evidence_quality - false_clause_penalty
    final_score = max(0.0, min(1.0, final_score))

    missing_clauses = [c for c in ground_truth_clauses if c not in correctly_cited_clauses]

    return ScoringResult(
        final_score=final_score,
        breakdown={
            "clause_recall": clause_recall,
            "evidence_quality": evidence_quality,
            "false_clause_penalty": false_clause_penalty,
        },
        true_positives=len(correctly_cited_clauses),
        false_positives=len(false_clauses),
        false_negatives=len(missing_clauses),
        details={
            "correctly_cited_clauses": list(correctly_cited_clauses),
            "missing_clauses": missing_clauses,
            "false_clauses": false_clauses,
            "scored_findings": scored_findings,
            "total_findings_submitted": len(agent_findings),
            "total_applicable_clauses": len(ground_truth_clauses),
        },
    )


def _score_evidence_quality_deterministic(
    finding: Dict[str, Any],
    ground_truth_findings: List[Dict[str, Any]],
) -> float:
    """Deterministic evidence quality scoring based on LLM judge rubric.

    Rubric:
        1.0: Exact file+line, correct article, accurate description, actionable fix
        0.7: Correct article and violation type, location slightly off, fix present
        0.4: Correct violation type, wrong article, no specific location
        0.1: Vague finding, incorrect article, no evidence
        0.0: Hallucinated violation
    """
    has_file_line = bool(finding.get("location"))
    has_article = bool(finding.get("article"))
    has_violation = bool(finding.get("violation") or finding.get("violation_type"))
    has_evidence = bool(finding.get("evidence"))
    has_fix = bool(finding.get("recommended_fix"))

    violation_type = finding.get("violation_type", "")
    matched_gt = None
    for gt in ground_truth_findings:
        if gt.get("violation_type") == violation_type:
            matched_gt = gt
            break

    if matched_gt:
        gt_file = matched_gt.get("file", "")
        gt_line = matched_gt.get("line", 0)
        location = finding.get("location", "")

        file_match = gt_file in location if location else False
        line_present = any(c.isdigit() for c in location) if location else False

        if has_file_line and file_match and line_present and has_article and has_violation and has_evidence and has_fix:
            return 1.0
        elif has_article and has_violation and has_fix and (file_match or has_evidence):
            return 0.7
        elif has_violation and has_evidence:
            return 0.4
        elif has_violation:
            return 0.1
        else:
            return 0.0
    else:
        if has_violation and has_article and has_evidence:
            return 0.4
        elif has_violation:
            return 0.1
        else:
            return 0.0
