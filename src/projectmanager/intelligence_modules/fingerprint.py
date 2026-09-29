from __future__ import annotations
from typing import Any

DEFAULT_WEIGHTS={
    "techniques":0.30,
    "ics_techniques":0.15,
    "sectors":0.10,
    "malware":0.10,
    "tools":0.08,
    "campaigns":0.07,
    "initial_access":0.07,
    "target_assets":0.05,
    "protocols":0.04,
    "it_ot_movement":0.04,
}

DEFAULT_SUPPORTED_MATCH={
    "similarity_weight":0.58,
    "coverage_weight":0.27,
    "evidence_quality_weight":0.15,
    "contradiction_penalty":0.12,
    "minimum_high_confidence_coverage":0.60,
    "minimum_medium_confidence_coverage":0.35,
}

def _get(obj,name,default=None):
    return obj.get(name,default) if isinstance(obj,dict) else getattr(obj,name,default)

def _norm(values):
    if values is None:return set()
    if isinstance(values,str):values=[values]
    return {str(x).strip().lower() for x in values if str(x).strip()}

def _jaccard(a,b):
    a,b=_norm(a),_norm(b)
    if not a and not b:return None
    if not a or not b:return 0.0
    return len(a&b)/len(a|b)

def _source_quality(extra:dict,actor:Any)->float:
    raw=extra.get("evidence_quality",extra.get("source_quality",None))
    if raw is not None:
        try:
            v=float(raw)
            if v>1:v/=100.0
            return max(0.0,min(1.0,v))
        except Exception:pass
    # Actor confidence is available across the existing CTI model and is used only
    # as a conservative fallback for source/evidence quality.
    try:return max(0.0,min(1.0,float(_get(actor,"confidence",50) or 50)/100.0))
    except Exception:return 0.5

class BehavioralActorFingerprintModule:
    module_id="behavioral_actor_fingerprint"
    name="Behavioral Actor Fingerprint & Similarity"
    version="1.1"
    category="Threat Intelligence"

    @classmethod
    def fingerprint(cls,actor:Any,enrichment:dict|None=None)->dict:
        enrichment=enrichment or {}
        aid=str(_get(actor,"id",""))
        store=enrichment.get("actor_fingerprints") or {}
        extra=dict(store.get(aid,{}) or {})
        lookup_names=[str(_get(actor,"name","")),*list(_get(actor,"aliases",[]) or [])]
        for key in lookup_names:
            candidate=store.get(key) or store.get(key.lower())
            if isinstance(candidate,dict):
                merged=dict(candidate);merged.update(extra);extra=merged
        provenance=[]
        refs=_get(actor,"references",[]) or []
        for ref in refs:
            source=_get(ref,"source","") or _get(ref,"title","") or _get(ref,"url","")
            if source:provenance.append(str(source))
        provenance.extend(str(x) for x in (extra.get("source_labels") or []) if str(x).strip())
        techniques=list(_get(actor,"techniques",[]) or [])
        return {
            "actor_id":aid,
            "name":str(_get(actor,"name","")),
            "aliases":list(_get(actor,"aliases",[]) or []),
            "techniques":sorted(_norm(techniques)),
            "ics_techniques":sorted(_norm(extra.get("ics_techniques",[]))),
            "sectors":sorted(_norm(_get(actor,"sectors",[]) or extra.get("sectors",[]))),
            "malware":sorted(_norm(_get(actor,"malware_ids",[]))),
            "tools":sorted(_norm(_get(actor,"tool_ids",[]))),
            "campaigns":sorted(_norm(_get(actor,"campaign_ids",[]))),
            "initial_access":sorted(_norm(extra.get("initial_access",[]))),
            "target_assets":sorted(_norm(extra.get("target_assets",[]))),
            "protocols":sorted(_norm(extra.get("protocols",[]))),
            "it_ot_movement":sorted(_norm(extra.get("it_ot_movement",[]))),
            "negative_evidence":sorted(_norm(extra.get("negative_evidence",[]))),
            "source_labels":sorted(set(provenance)),
            "evidence_quality":round(_source_quality(extra,actor),3),
            "confidence":int(_get(actor,"confidence",50) or 50),
        }

    @classmethod
    def _settings(cls,profile):
        weights=dict(DEFAULT_WEIGHTS);supported=dict(DEFAULT_SUPPORTED_MATCH)
        if profile:
            weights.update({k:float(v) for k,v in (profile.get("weights") or {}).items() if k in weights})
            supported.update({k:float(v) for k,v in (profile.get("supported_match") or {}).items() if k in supported})
        return weights,supported

    @classmethod
    def compare(cls,reference:dict,candidate:dict,profile:dict|None=None)->dict:
        weights,supported=cls._settings(profile)
        total=0.0;used_weight=0.0;components={};comparable=0
        matched={};contradictory={};missing={};observed_unmatched={}
        ref_populated=[field for field in weights if _norm(reference.get(field))]
        candidate_populated=[field for field in weights if _norm(candidate.get(field))]

        for field,weight in weights.items():
            ref_values=_norm(reference.get(field));cand_values=_norm(candidate.get(field))
            if not ref_values:
                continue
            if not cand_values:
                missing[field]=sorted(ref_values)
                continue

            comparable+=1;used_weight+=weight
            intersection=ref_values & cand_values
            unmatched=ref_values-cand_values
            union=ref_values | cand_values
            sim=(len(intersection)/len(union)) if union else 0.0
            total+=sim*weight
            components[field]=round(sim*100,1)
            if intersection:matched[field]=sorted(intersection)
            if unmatched:observed_unmatched[field]=sorted(unmatched)

        raw_similarity=(total/used_weight) if used_weight else 0.0

        # Explicit negative evidence is the only automatic contradiction source.
        # Ordinary absent actor knowledge remains unknown rather than contradiction.
        negatives=_norm(reference.get("negative_evidence"))
        for field in weights:
            hits=negatives & _norm(candidate.get(field))
            if hits:contradictory[field]=sorted(hits)
        contradiction_count=sum(len(v) for v in contradictory.values())
        contradiction_factor=min(1.0,contradiction_count/max(1,len(negatives))) if negatives else 0.0

        reference_dimensions=len(ref_populated)

        # Coverage describes how much of the *observed evidence* can actually be
        # compared with the candidate. It is intentionally evidence-item based,
        # not weight based: a high configured technique weight must not make a
        # sparsely populated candidate look well covered.
        reference_weight=sum(weights[field] for field in ref_populated)
        comparable_weight=sum(weights[field] for field in ref_populated if _norm(candidate.get(field)))
        weighted_coverage_ratio=(comparable_weight/reference_weight) if reference_weight else 0.0
        observed_item_count=sum(len(_norm(reference.get(field))) for field in ref_populated)
        comparable_item_count=sum(
            len(_norm(reference.get(field)))
            for field in ref_populated
            if _norm(candidate.get(field))
        )
        matched_item_count=sum(len(values) for values in matched.values())
        # Analyst-facing Coverage is the share of the observed evidence actually
        # covered by supporting evidence for this specific candidate. Mere data
        # availability is retained separately as comparable_ratio and must not
        # make every actor with the same populated dimensions show one identical
        # coverage percentage.
        coverage_ratio=(matched_item_count/observed_item_count) if observed_item_count else 0.0
        comparable_ratio=(comparable_item_count/observed_item_count) if observed_item_count else 0.0
        dimension_coverage_ratio=(comparable/reference_dimensions) if reference_dimensions else 0.0
        evidence_quality=max(0.0,min(1.0,float(candidate.get("evidence_quality",candidate.get("confidence",50)/100.0) or 0.0)))

        # Supported Match must be supported by *matching evidence*. Missing actor
        # knowledge, candidate source quality and mere comparability may affect
        # confidence, but they must never create positive behavioral support.
        # Each populated observed dimension contributes its configured weight; a
        # missing candidate dimension therefore contributes zero rather than being
        # removed from the denominator.
        supported_evidence=0.0
        for field in ref_populated:
            ref_values=_norm(reference.get(field));cand_values=_norm(candidate.get(field))
            if not cand_values:
                continue
            union=ref_values | cand_values
            sim=(len(ref_values & cand_values)/len(union)) if union else 0.0
            supported_evidence+=weights[field]*sim
        direct_support=(supported_evidence/reference_weight) if reference_weight else 0.0

        # Explicit negative evidence can reduce existing support, but can never
        # turn a zero-evidence candidate into a positive match.
        contradiction_multiplier=max(0.0,1.0-contradiction_factor*supported["contradiction_penalty"])
        supported_score=max(0.0,min(1.0,direct_support*contradiction_multiplier))

        matched_items=matched_item_count
        if matched_items and coverage_ratio>=supported["minimum_high_confidence_coverage"] and evidence_quality>=0.60 and supported_score>=0.60:
            analytical_confidence="HIGH"
        elif matched_items and coverage_ratio>=supported["minimum_medium_confidence_coverage"] and supported_score>=0.35:
            analytical_confidence="MEDIUM"
        else:
            analytical_confidence="LOW"

        if supported_score>=0.70 and analytical_confidence!="LOW":
            classification="Best Supported Behavioral Match"
        elif supported_score>=0.40:
            classification="Potentially Related Tradecraft"
        else:
            classification="Insufficient Evidence for Attribution"

        return {
            "actor_id":candidate.get("actor_id",""),
            "name":candidate.get("name",""),
            "aliases":candidate.get("aliases",[]),
            "supported_match_score":round(supported_score*100,1),
            "raw_similarity":round(raw_similarity*100,1),
            # compatibility with previous versions
            "behavioral_similarity":round(raw_similarity*100,1),
            "analytical_confidence":analytical_confidence,
            "classification":classification,
            "evidence_quality":round(evidence_quality*100,1),
            "coverage":{
                "comparable_dimensions":comparable,
                "reference_dimensions":reference_dimensions,
                "candidate_dimensions":len(candidate_populated),
                "possible_dimensions":len(weights),
                "observed_evidence_items":observed_item_count,
                "matched_evidence_items":matched_item_count,
                "comparable_evidence_items":comparable_item_count,
                "ratio":round(coverage_ratio*100,1),
                "comparable_ratio":round(comparable_ratio*100,1),
                "dimension_ratio":round(dimension_coverage_ratio*100,1),
                "weighted_ratio":round(weighted_coverage_ratio*100,1),
            },
            "components":components,
            "supporting_evidence":matched,
            "contradictory_evidence":contradictory,
            "missing_unknown_evidence":missing,
            "observed_not_in_candidate_profile":observed_unmatched,
            "negative_evidence_penalty":round(contradiction_factor*supported["contradiction_penalty"]*100,1),
            "score_breakdown":{
                "raw_similarity":round(raw_similarity*100,1),
                "coverage":round(coverage_ratio*100,1),
                "comparable_coverage":round(comparable_ratio*100,1),
                "evidence_quality":round(evidence_quality*100,1),
                "direct_evidence_support":round(direct_support*100,1),
                "weighted_comparable_coverage":round(weighted_coverage_ratio*100,1),
                "dimension_coverage":round(dimension_coverage_ratio*100,1),
                "contradiction_factor":round(contradiction_factor*100,1),
                "supported_match":round(supported_score*100,1),
                "weights":supported,
            },
            "sources_provenance":list(candidate.get("source_labels",[]) or []),
            "interpretation":(
                f"{classification}. Behavioral comparison supports hypothesis generation only. "
                "The score is not actor attribution, identity, responsibility or proof of involvement."
            ),
        }

    @classmethod
    def rank(cls,reference_actor,actors,enrichment=None,profile=None,limit=20):
        ref=cls.fingerprint(reference_actor,enrichment)
        ref_ids={ref["actor_id"]};ref_names=_norm([ref["name"],*ref["aliases"]])
        rows=[]
        for actor in actors:
            fp=cls.fingerprint(actor,enrichment)
            if fp["actor_id"] in ref_ids:continue
            if ref_names & _norm([fp["name"],*fp["aliases"]]):continue
            rows.append(cls.compare(ref,fp,profile))
        rows.sort(key=lambda x:(-x["supported_match_score"],-x["coverage"]["ratio"],-x["raw_similarity"],x["name"].lower()))
        return {"analysis_type":"supported_behavioral_match","reference":ref,"results":rows[:max(1,int(limit))],
                "profile":profile or {"name":"Default","weights":DEFAULT_WEIGHTS,"supported_match":DEFAULT_SUPPORTED_MATCH},
                "disclaimer":"Best Supported Behavioral Match is hypothesis support, not attribution."}

    @classmethod
    def normalize_observed_context(cls,observed:dict)->dict:
        if not isinstance(observed,dict):
            raise ValueError("Observed behavior context moet een JSON-object zijn.")
        nested=observed.get("fingerprint")
        source=nested if isinstance(nested,dict) else observed
        fields=list(DEFAULT_WEIGHTS)+["negative_evidence"]
        normalized={field:sorted(_norm(source.get(field,[]))) for field in fields}
        normalized["confidence"]=int(source.get("confidence",observed.get("confidence",70)) or 70)
        normalized["label"]=str(observed.get("actor") or observed.get("name") or source.get("name") or "Observed behavior")
        normalized["sources_provenance"]=list(source.get("sources_provenance",observed.get("sources_provenance",[])) or [])
        usable={field:normalized[field] for field in DEFAULT_WEIGHTS if normalized.get(field)}
        if not usable:
            raise ValueError("Geen bruikbare behavioral fingerprint gevonden. Vul minimaal één van deze velden: "+", ".join(DEFAULT_WEIGHTS.keys()))
        normalized["_recognized_dimensions"]=sorted(usable)
        normalized["_recognized_counts"]={k:len(v) for k,v in usable.items()}
        return normalized

    @classmethod
    def rank_observed_context(cls,observed:dict,actors,enrichment=None,profile=None,limit=20):
        observed=cls.normalize_observed_context(observed)
        ref={
            "actor_id":"observed-context","name":observed["label"],"aliases":[],
            "techniques":observed["techniques"],"ics_techniques":observed["ics_techniques"],
            "sectors":observed["sectors"],"malware":observed["malware"],"tools":observed["tools"],
            "campaigns":observed["campaigns"],"initial_access":observed["initial_access"],
            "target_assets":observed["target_assets"],"protocols":observed["protocols"],
            "it_ot_movement":observed["it_ot_movement"],"negative_evidence":observed["negative_evidence"],
            "confidence":observed["confidence"],"recognized_counts":observed["_recognized_counts"],
            "sources_provenance":observed["sources_provenance"],
        }
        rows=[cls.compare(ref,cls.fingerprint(a,enrichment),profile) for a in actors]
        rows.sort(key=lambda x:(-x["supported_match_score"],-x["coverage"]["ratio"],-x["raw_similarity"],x["name"].lower()))
        return {"analysis_type":"supported_behavioral_match","reference":ref,"results":rows[:max(1,int(limit))],
                "profile":profile or {"name":"Default","weights":DEFAULT_WEIGHTS,"supported_match":DEFAULT_SUPPORTED_MATCH},
                "disclaimer":"Best Supported Behavioral Match is hypothesis support, not attribution."}
