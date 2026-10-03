# Research foundations

The following work informs the assurance design. Implementing a screening method does not establish the coverage or guarantees reported in its paper.

The references below inform components of the proposed architecture. Research findings do not transfer automatically to this framework, a different dataset or a different detector. Each adapted method requires its own evaluation. Brief descriptions identify intended use, not a claim of endorsement or standards compliance.

### 36.1 Assurance, representations and data quality

1. **Hawkins et al., Guidance on the Assurance of Machine Learning in Autonomous Systems (AMLAS), 2021.** Claim/evidence structuring and contextual ML assurance. [Paper](https://arxiv.org/abs/2102.01564)
2. **Oquab et al., DINOv2: Learning Robust Visual Features without Supervision, 2023.** Frozen visual features for neighbourhood and reference analysis. [Paper](https://arxiv.org/abs/2304.07193)
3. **DINOv3, 2025.** Candidate newer representation family to compare under frozen adapter/calibration conditions. [Technical report](https://arxiv.org/abs/2508.10104)
4. **Northcutt, Jiang and Chuang, Confident Learning: Estimating Uncertainty in Dataset Labels, 2019 preprint.** Label-quality estimation under explicit noise/prediction assumptions. [Paper](https://arxiv.org/abs/1911.00068)
5. **Park et al., TRAK: Attributing Model Behavior at Scale, 2023.** Training-data influence ranking for suitable differentiable models. [Paper](https://arxiv.org/abs/2303.14186)

### 36.2 Backdoors and evaluation

6. **Gu et al., BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain, 2017.** Motivation for testing conditional failures beyond benign accuracy. [Paper](https://arxiv.org/abs/1708.06733)
7. **Wang et al., Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural Networks, IEEE S&P, 2019.** Trigger reconstruction and anomalous target behaviour. [Author-hosted paper](https://people.cs.uchicago.edu/~ravenben/publications/pdf/backdoor-sp19.pdf)
8. **Tran, Li and Madry, Spectral Signatures in Backdoor Attacks, 2018.** Representation-level outlier evidence. [Paper](https://arxiv.org/abs/1811.00636)
9. **Chen et al., Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering, 2018 preprint.** Activation-space subgroup investigation. [Paper](https://arxiv.org/abs/1811.03728)
10. **Hayase et al., SPECTRE: Defending Against Backdoor Attacks Using Robust Statistics, 2021.** Robust covariance as an additional screening candidate. [Paper](https://arxiv.org/abs/2104.11315)
11. **Gao et al., STRIP: A Defence Against Trojan Attacks on Deep Neural Networks, 2019.** Input perturbation and entropy-based evidence under suitable assumptions. [Paper](https://arxiv.org/abs/1902.06531)
12. **Guo et al., SCALE-UP: An Efficient Black-box Input-level Backdoor Detection via Analyzing Scaled Prediction Consistency, 2023.** Label-only black-box input checks in its studied setting. [Paper](https://arxiv.org/abs/2302.03251)
13. **Chan et al., BadDet: Backdoor Attacks on Object Detection, 2022.** Detection-specific threat types and evaluation objectives. [Paper](https://arxiv.org/abs/2205.14497)
14. **Dunnett et al., BadDet+: Robust Backdoor Attacks for Object Detection, 2026 preprint.** Position/scale and physical robustness as evaluation challenges. [Paper](https://arxiv.org/abs/2601.21066)
15. **Wu et al., BackdoorBench: A Comprehensive Benchmark of Backdoor Learning, 2022.** Standardised attack/defence evaluation design. [Paper](https://arxiv.org/abs/2206.12654)
16. **Pang et al., TrojanZoo: Towards Unified, Holistic, and Practical Evaluation of Neural Backdoors, EuroS&P 2022; preprint 2020.** Evaluation breadth and adaptive-defence limitations. [Paper](https://arxiv.org/abs/2012.09302)

### 36.3 Differential testing, shift and calibration

17. **Pei et al., DeepXplore: Automated Whitebox Testing of Deep Learning Systems, 2017.** Differential test-generation principles. [Paper](https://arxiv.org/abs/1705.06640)
18. **Tian et al., DeepTest: Automated Testing of Deep-Neural-Network-driven Autonomous Cars, 2017 preprint.** Metamorphic testing under controlled transformations. [Paper](https://arxiv.org/abs/1708.08559)
19. **Rabanser, Günnemann and Lipton, Failing Loudly: An Empirical Study of Methods for Detecting Dataset Shift, 2018 preprint.** Distribution-change evaluation and representation choices. [Paper](https://arxiv.org/abs/1810.11953)
20. **Gretton et al., A Kernel Two-Sample Test, JMLR, 2012.** MMD-based distribution comparison. [Paper](https://www.jmlr.org/papers/v13/gretton12a.html)
21. **Guo, Pleiss, Sun and Weinberger, On Calibration of Modern Neural Networks, ICML, 2017.** Prediction calibration and temperature scaling. [Paper](https://proceedings.mlr.press/v70/guo17a.html)
22. **Angelopoulos and Bates, A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification, 2021 preprint.** Prediction sets and explicit coverage assumptions. [Paper](https://arxiv.org/abs/2107.07511)
23. **Ries et al., Probabilistic Object Detection with Conformal Prediction, PMLR 329, 2026.** Detection-specific class/localisation uncertainty as an evaluated extension. [Paper](https://proceedings.mlr.press/v329/ries26a.html)

### 36.4 Provenance, cryptography and governance

24. **Torres-Arias et al., in-toto: Providing farm-to-table guarantees for bits and bytes, USENIX Security, 2019.** Artifact/step lineage and supply-chain verification. [Paper](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias)
25. **RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), 2017.** Ed25519 signature specification. [Standard](https://www.rfc-editor.org/rfc/rfc8032)
26. **RFC 8785: JSON Canonicalization Scheme (JCS), 2020.** Canonical bytes for interoperable signing. [Standard](https://www.rfc-editor.org/rfc/rfc8785)
27. **RFC 9162: Certificate Transparency Version 2.0, 2021.** Inclusion, consistency and signed-checkpoint concepts adapted for an offline audit log. [Standard](https://www.rfc-editor.org/rfc/rfc9162.html)
28. **NIST AI RMF 1.0, 2023.** Context, measurement and risk-management framing; use does not imply certification. [Official publication](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
29. **NIST AI 100-2 E2025: Adversarial Machine Learning—A Taxonomy and Terminology of Attacks and Mitigations, 2025.** Threat classes and consistent terminology. [Official publication](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
30. **MITRE ATLAS.** Living vocabulary for AI-related tactics and techniques; snapshot/version the locally used material. [Official knowledge base](https://atlas.mitre.org/)


The optional attribution adapter follows the official [TRAK quickstart](https://trak.readthedocs.io/en/latest/quickstart.html) and [API reference](https://trak.readthedocs.io/en/latest/trak.html). It uses CPU projection, deterministic sample membership and checkpoint-bound scoring; compatibility is tested at execution and can remain unresolved.
