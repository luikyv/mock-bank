# mock-bank

Mock Bank is a mock implementation of the Open Finance Brasil API specifications. It serves as a reference platform for ecosystem participants to develop, test, and validate their applications in a controlled environment, without depending on real financial institutions.


## APIs Available

| API | Version | Status |
|-----|---------|--------|
| Consents | [3.2.0](https://openbanking-brasil.github.io/openapi/swagger-apis/consents/3.2.0.yml) | Implemented |
| Accounts | [2.4.2](https://raw.githubusercontent.com/OpenBanking-Brasil/openapi/main/swagger-apis/accounts/2.4.2.yml) | Implemented |
| Customers | [2.2.1](https://raw.githubusercontent.com/OpenBanking-Brasil/openapi/main/swagger-apis/customers/2.2.1.yml) | Developing |
| Loans | [2.4.0](https://raw.githubusercontent.com/OpenBanking-Brasil/openapi/main/swagger-apis/loans/2.4.0.yml) | Developing |
| Resources | [3.0.0](https://openbanking-brasil.github.io/openapi/swagger-apis/resources/3.0.0.yml) | Developing |
| Payments | [4.0.0](https://raw.githubusercontent.com/OpenBanking-Brasil/openapi/main/swagger-apis/payments/4.0.0.yml) | Developing |
| Automatic Payments | [2.1.0](https://raw.githubusercontent.com/OpenBanking-Brasil/all-services-repo/refs/heads/main/API%20Automatic%20Payments%20-%20Open%20Finance%20Brasil/2.1.0.yaml) | Developing |
| Enrollments | [2.1.0](https://raw.githubusercontent.com/OpenBanking-Brasil/openapi/refs/heads/main/swagger-apis/enrollments/2.1.0.yml) | Developing |

## URLs
| URL                          | Description                                    | mTLS  |
|------------------------------|------------------------------------------------|-------|
| https://app.mockbank.{HOST}           | App Frontend                                   | No    |
| https://app.mockbank.{HOST}/api       | App Backend                                    | No    |
| https://auth.mockbank.{HOST}          | Authorization Server                           | No    |
| https://matls-auth.mockbank.{HOST}    | Authorization Server                           | Yes   |
| https://matls-api.mockbank.{HOST}     | Bank Backend                                   | Yes   |

## Users

Mock Bank comes with predefined users preloaded with test data to facilitate development and testing across all APIs.

All users listed below share the default password: `P@ssword01`.

| Username              | CPF           | CNPJ              | Description                                  |
|-----------------------|---------------|-------------------|----------------------------------------------|
| alice@email.com | 761.092.776-73 | 50.685.362/0006-73 | Primary test user with resources in all APIs |
| bob@email.com | 875.174.004-44 | N/A | Test user with joint account for multiple consents scenarios |

## Getting Started

### Prerequisites
- Go 1.24+ (For development only)
- Docker and Docker Compose
- Git

Add the entries below to `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```bash
127.0.0.1 app.mockbank.local
127.0.0.1 auth.mockbank.local
127.0.0.1 matls-auth.mockbank.local
127.0.0.1 matls-api.mockbank.local
127.0.0.1 directory.local
127.0.0.1 keystore.local
127.0.0.1 database.local
127.0.0.1 aws.local
```

### Quick Start

1. **Clone and setup**:
   ```bash
   git clone https://github.com/luikyv/mock-bank
   cd mock-bank
   make setup
   ```

2. **Run the application**:
   ```bash
   make run
   ```

The application will be available at:
- Frontend: https://app.mockbank.local
- Bank Server: https://matls-api.mockbank.local
- Authorization Server: https://auth.mockbank.local

### Development Setup

For development with additional tools:
```bash
make setup-dev
```

### Running with Conformance Suite

To run MockBank with the Open Finance Conformance Suite:

1. **Setup the Conformance Suite**:
   ```bash
   make setup-cs
   ```

2. **Run with Conformance Suite**:
   ```bash
   make run-with-cs
   ```

## TODO
- Add doc.go's.
- Finish accounts and loans.
- Improve the html.
- Update swaggers to undo modifications.
- Improve loops that query the db.
- Remove descriptions.
- Improve error handling.
- Add logs.
- https://openfinancebrasil.atlassian.net/wiki/spaces/OF/pages/246120449/EN+Open+Finance+Brasil+Financial-grade+API+Dynamic+Client+Registration+2.0+RC1+Implementers+Draft+3
