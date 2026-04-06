export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type VerificationStatus = 'confirmed' | 'likely' | 'false_positive' | 'inconclusive';

export type ScanStep = {
	t: number;
	level: 'info' | 'warn' | 'error';
	message: string;
};

export type EvidenceItem = { type: string; detail: string };

export type RuleHit = {
	ruleId: string;
	title: string;
	severity: Severity;
	category: string;
	description: string;
	remediation: string;
	confidence: Confidence;
	filePath: string;
	line: number;
	excerpt: string;
	evidence: EvidenceItem[];
};
