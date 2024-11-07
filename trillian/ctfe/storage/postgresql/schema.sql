-- Copyright 2024 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- PostgreSQL / MariaDB version of the CTFE database schema

-- "IssuanceChain" table contains the hash and value pairs of the issuance chain.
CREATE TABLE IF NOT EXISTS `IssuanceChain` (
  -- Hash of the chain of intermediate certificates and root certificates.
  `IdentityHash` VARBINARY(255) NOT NULL,
  -- Chain data of intermediate certificates and root certificates.
  `ChainValue`   LONGBLOB NOT NULL,
  PRIMARY KEY (`IdentityHash`)
);
