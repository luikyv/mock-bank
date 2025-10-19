import type {
  User,
  MockUserRequest,
  AccountRequest,
  Resource,
  MockUsers,
  Consents,
  Accounts,
  Resources,
  Enrollments,
} from "./types";
import { ErrorCode, ErrorInfo, type ResponseError } from "./errors";
import { v4 as uuidv4 } from "uuid";

export async function tryFetch<T>(
  input: RequestInfo,
  init?: RequestInit
): Promise<T> {
  const interactionId = uuidv4();
  init = init ?? {};
  init.headers = {
    ...(init.headers instanceof Headers
      ? Object.fromEntries(init.headers.entries())
      : init.headers),
    "x-fapi-interaction-id": interactionId,
  };
  const res = await fetch(input, init);

  if (res.status >= 500) {
    throw new ErrorInfo(
      ErrorCode.INTERNAL_ERROR,
      ErrorCode.INTERNAL_ERROR,
      interactionId
    );
  }

  if (res.status == 401) {
    throw new ErrorInfo(
      ErrorCode.UNAUTHENTICATED,
      ErrorCode.UNAUTHENTICATED,
      interactionId
    );
  }

  const body = res.status != 204 ? await res.json() : {};
  if (!res.ok) {
    const respError = body as ResponseError;
    throw new ErrorInfo(
      respError.errors[0].code,
      respError.errors[0].detail,
      interactionId
    );
  }

  return body as T;
}

export async function fetchMockUsers(
  orgId: string,
  pageUrl?: string
): Promise<MockUsers> {
  return await tryFetch(pageUrl ?? `/api/orgs/${orgId}/users?page=1&size=10`, {
    credentials: "include",
  });
}

export async function createMockUser(
  user: MockUserRequest,
  orgId: string
): Promise<void> {
  await tryFetch(`/api/orgs/${orgId}/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data: user }),
    credentials: "include",
  });
  return;
}

export async function updateMockUser(
  userId: string,
  user: MockUserRequest,
  orgId: string
): Promise<void> {
  await tryFetch(`/api/orgs/${orgId}/users/${userId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data: user }),
    credentials: "include",
  });
  return;
}

export async function deleteMockUser(
  userId: string,
  orgId: string
): Promise<void> {
  return await tryFetch(`/api/orgs/${orgId}/users/${userId}`, {
    method: "DELETE",
    credentials: "include",
  });
}

export async function fetchConsents(
  userId: string,
  orgId: string,
  pageUrl?: string
): Promise<Consents> {
  return await tryFetch(
    pageUrl ?? `/api/orgs/${orgId}/users/${userId}/consents`,
    {
      credentials: "include",
    }
  );
}

export async function fetchEnrollments(
  userId: string,
  orgId: string,
  pageUrl?: string
): Promise<Enrollments> {
  return await tryFetch(
    pageUrl ?? `/api/orgs/${orgId}/users/${userId}/enrollments`,
    {
      credentials: "include",
    }
  );
}

export async function createMockAccount(
  account: AccountRequest,
  userId: string,
  orgId: string
): Promise<void> {
  await tryFetch(`/api/orgs/${orgId}/users/${userId}/accounts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data: account }),
    credentials: "include",
  });
  return;
}

export async function updateMockAccount(
  accountId: string,
  userId: string,
  orgId: string,
  account: AccountRequest
): Promise<void> {
  await tryFetch(`/api/orgs/${orgId}/users/${userId}/accounts/${accountId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data: account }),
    credentials: "include",
  });
  return;
}

export async function fetchMockAccounts(
  userId: string,
  orgId: string,
  pageUrl?: string
): Promise<Accounts> {
  return await tryFetch(
    pageUrl ?? `/api/orgs/${orgId}/users/${userId}/accounts`,
    {
      credentials: "include",
    }
  );
}

export async function deleteMockAccount(
  accountId: string,
  userId: string,
  orgId: string
): Promise<void> {
  return await tryFetch(
    `/api/orgs/${orgId}/users/${userId}/accounts/${accountId}`,
    {
      method: "DELETE",
      credentials: "include",
    }
  );
}

export async function fetchAuthUrl(): Promise<string> {
  const res: { data: { url: string } } = await tryFetch(
    "/api/directory/auth-url"
  );
  return res.data.url;
}

export async function fetchUser(): Promise<User> {
  const res: { data: User } = await tryFetch(`/api/me`, {
    credentials: "include",
  });
  return res.data;
}

export async function fetchMockResources(
  userId: string,
  orgId: string,
  pageUrl?: string
): Promise<Resources> {
  return await tryFetch(
    pageUrl ?? `/api/orgs/${orgId}/users/${userId}/resources`,
    {
      credentials: "include",
    }
  );
}

export async function updateMockResource(
  userId: string,
  orgId: string,
  resource: Resource
): Promise<void> {
  return await tryFetch(
    `/api/orgs/${orgId}/users/${userId}/resources/${resource.resourceId}/consents/${resource.consentId}?type=${resource.type}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { status: resource.status } }),
      credentials: "include",
    }
  );
}

export function isValidCpf(cpf: string): boolean {
  return /^\d{11}$/.test(cpf);
}

export function isValidCnpj(cnpj: string): boolean {
  return /^\d{14}$/.test(cnpj);
}

export function isValidAccountNumber(number: string): boolean {
  return /^\d{8,10}$/.test(number);
}

export function isValidAmount(amount: string): boolean {
  return /^\d+(\.\d{1,2})?$/.test(amount) && parseFloat(amount) >= 0;
}
