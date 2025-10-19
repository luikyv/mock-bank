export interface Links {
  self?: string;
  next?: string;
  prev?: string;
}

export interface Organization {
  id: string;
  name: string;
}

export interface User {
  id: string;
  username: string;
  organizations: Record<string, Organization>;
}

export interface MockUserRequest {
  username: string;
  name: string;
  cpf: string;
  cnpj?: string;
  description?: string;
}

export interface MockUser {
  id: string;
  username: string;
  name: string;
  cpf: string;
  cnpj?: string;
  description?: string;
}

export interface MockUsers {
  data: MockUser[];
  links: Links;
}

export enum ConsentStatus {
  AUTHORIZED = "AUTHORISED",
  AWAITING_AUTHORIZATION = "AWAITING_AUTHORISATION",
  REVOKED = "REVOKED",
}

export interface Consent {
  consentId: string;
  status: ConsentStatus;
  permissions: string[];
  creationDateTime: string;
  expirationDateTime: string;
  statusUpdateDateTime: string;
  clientId: string;
  userId: string;
}

export interface Consents {
  data: Consent[];
  links: Links;
}

export enum AccountType {
  CHECKING = "CONTA_DEPOSITO_A_VISTA",
  SAVINGS = "CONTA_POUPANCA",
  PREPAID = "CONTA_PAGAMENTO_PRE_PAGA",
}

export enum AccountSubtype {
  INDIVIDUAL = "INDIVIDUAL",
  JOINT_SIMPLE = "CONJUNTA_SIMPLES",
  JOINT_SOLIDARY = "CONJUNTA_SOLIDARIA",
}

export interface Account {
  accountId: string;
  number: string;
  subtype: AccountSubtype;
  availableAmount: string;
  blockedAmount: string;
  automaticallyInvestedAmount: string;
  checkDigit: string;
  branchCode: string;
  type: AccountType;
}

export interface Accounts {
  data: Account[];
  links: Links;
}

export interface AccountRequest {
  number: string;
  type: AccountType;
  subtype: AccountSubtype;
  availableAmount: string;
  blockedAmount: string;
  automaticallyInvestedAmount: string;
}

export enum ResourceStatus {
  AVAILABLE = "AVAILABLE",
  UNAVAILABLE = "UNAVAILABLE",
  TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE",
  PENDING_AUTHORISATION = "PENDING_AUTHORISATION",
}

export interface Resource {
  consentId: string;
  resourceId: string;
  status: ResourceStatus;
  type: string;
  creationDateTime: string;
}

export interface Resources {
  data: Resource[];
  links: Links;
}

export interface Enrollment {
  enrollmentId: string;
  status: EnrollmentStatus;
  permissions: string[];
  creationDateTime: string;
  expirationDateTime: string;
  clientId: string;
  userId: string;
}

export interface Enrollments {
  data: Enrollment[];
  links: Links;
}

export enum EnrollmentStatus {
  AWAITING_RISK_SIGNALS = "AWAITING_RISK_SIGNALS",
  AWAITING_ACCOUNT_HOLDER_VALIDATION = "AWAITING_ACCOUNT_HOLDER_VALIDATION",
  AWAITING_ENROLLMENT = "AWAITING_ENROLLMENT",
  AUTHORISED = "AUTHORISED",
  REVOKED = "REVOKED",
  REJECTED = "REJECTED",
}