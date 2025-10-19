import { useToast } from "vue-toastification";
import { type Router } from "vue-router";

export enum ErrorCode {
  USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS",
  ACCOUNT_ALREADY_EXISTS = "ACCOUNT_ALREADY_EXISTS",
  UNAUTHENTICATED = "UNAUTHENTICATED",
  INTERNAL_ERROR = "INTERNAL_ERROR",
}

export function handleError(router: Router) {
  const toast = useToast();

  return (err: unknown) => {
    if (!(err instanceof ErrorInfo)) {
      toast.error("Something went wrong :(");
      console.log(err);
      return;
    }

    const errInfo = err as ErrorInfo;
    console.log(errInfo.interactionId);
    switch (errInfo.code) {
      case ErrorCode.UNAUTHENTICATED:
        toast.info(`Please log in again`);
        router.push("/login");
        break;
      case ErrorCode.USER_ALREADY_EXISTS:
        toast.error(`User already exists`);
        break;
      case ErrorCode.ACCOUNT_ALREADY_EXISTS:
        toast.error(`Account already exists`);
        break;
      default:
        toast.error(
          `${errInfo.message} \n\nInteraction ID: ${errInfo.interactionId}`
        );
        break;
    }
  };
}

export class ErrorInfo extends Error {
  code: ErrorCode;
  interactionId?: string;
  constructor(code: ErrorCode, message: string, interactionId?: string) {
    super(message);
    this.code = code;
    this.interactionId = interactionId;
  }
}

export interface ResponseError extends Error {
  errors: {
    code: ErrorCode;
    detail: string;
  }[];
}
