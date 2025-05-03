# Presidio Anonymizer for NestJS

[![npm version](https://img.shields.io/npm/v/presidio-anonymizer-nestjs.svg)](https://www.npmjs.com/package/presidio-anonymizer-nestjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A NestJS module and service for anonymizing and de-anonymizing sensitive information in text using Microsoft's Presidio services.

## Overview

This package provides a seamless integration of Microsoft's Presidio analyzer and anonymizer services into NestJS applications. It helps identify and anonymize personally identifiable information (PII) in text content while maintaining a mapping for later de-anonymization if needed.

## Features

- 🔍 **PII Detection**: Identifies multiple types of sensitive information including names, phone numbers, emails, credit cards, addresses, and more
- 🔒 **Text Anonymization**: Masks or replaces detected PII with configurable anonymization methods
- 🔄 **De-anonymization Support**: Maintains a mapping to restore original text when needed
- ⚙️ **Flexible Configuration**: Configure different anonymization strategies per entity type
- 🚀 **NestJS Integration**: Easy to use within any NestJS application
- 💪 **Resilient**: Built-in retry mechanisms and error handling

## Installation

```bash
npm install presidio-anonymizer-nestjs
```

## Prerequisites

This module is designed to work with Microsoft's Presidio services. You'll need:

1. Presidio Analyzer service running (defaults to http://localhost:5001)
2. Presidio Anonymizer service running (defaults to http://localhost:5002)

You can run these services using Docker:

```bash
docker pull mcr.microsoft.com/presidio-analyzer
docker pull mcr.microsoft.com/presidio-anonymizer

docker run -d -p 5001:3000 mcr.microsoft.com/presidio-analyzer:latest
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-anonymizer:latest
```

## Usage

### Importing the Module

```typescript
import { Module } from '@nestjs/common';
import { PresidioAnonymizerModule } from 'presidio-anonymizer-nestjs';

@Module({
  imports: [
    PresidioAnonymizerModule.forRoot({
      analyzerUrl: 'http://localhost:5001',
      anonymizerUrl: 'http://localhost:5002',
    }),
  ],
})
export class AppModule {}
```

### Using the Service

```typescript
import { Injectable } from '@nestjs/common';
import { AnonymizerService } from 'presidio-anonymizer-nestjs';

@Injectable()
export class YourService {
  constructor(private readonly anonymizerService: AnonymizerService) {}

  async processText(text: string) {
    // Anonymize text
    const { anonymizedText, entitiesFound } = await this.anonymizerService.anonymizeText(text);
    
    // Do something with anonymized text...
    console.log('Anonymized:', anonymizedText);
    
    // Get all entities that were found
    const entities = this.anonymizerService.getSensitiveEntities();
    console.log('Entities found:', entities);
    
    // Later, de-anonymize if needed
    const originalText = this.anonymizerService.deanonymizeText(anonymizedText);
    console.log('De-anonymized:', originalText);
    
    return {
      anonymized: anonymizedText,
      original: originalText,
      entities,
    };
  }
}
```

### Environment Variables

You can configure the service using environment variables:

- `PRESIDIO_ANALYZER_URL`: URL of the Presidio Analyzer service (defaults to http://localhost:5001)
- `PRESIDIO_ANONYMIZER_URL`: URL of the Presidio Anonymizer service (defaults to http://localhost:5002)

## Supported Entity Types

The following PII entity types are supported:

- PERSON
- PHONE_NUMBER
- EMAIL_ADDRESS
- CREDIT_CARD
- DATE_TIME
- LOCATION
- ORGANIZATION
- US_SSN
- US_BANK_ACCOUNT
- US_DRIVER_LICENSE
- US_ITIN
- US_PASSPORT
- UK_NHS
- IP_ADDRESS
- IBAN_CODE
- CRYPTO
- URL
- MEDICAL_LICENSE
- MEDICAL_RECORD
- AGE
- ADDRESS
- NRP

## Anonymization Methods

The service supports different anonymization methods per entity:

- **Replace**: Replace the entity with a placeholder (e.g., [PERSON], [PHONE])
- **Mask**: Mask part of the entity with a chosen character (e.g., john***@email.com)
- **Hash**: Hash the entity value using SHA-256

## API Reference

### AnonymizerService

#### `anonymizeText(text: string): Promise<{ anonymizedText: string; entitiesFound: boolean }>`

Analyzes input text for PII, anonymizes detected entities, and maintains a mapping for later deanonymization.

- **Parameters**:
  - `text`: The text to anonymize
- **Returns**: Object with anonymized text and a flag indicating if entities were found

#### `deanonymizeText(anonymizedText: string): string`

Replaces anonymized placeholders with their original values using the entity mapping from the last anonymization.

- **Parameters**:
  - `anonymizedText`: Previously anonymized text
- **Returns**: The original text with PII restored

#### `getSensitiveEntities(): SensitiveEntity[]`

Returns all sensitive entities found in the last anonymization.

- **Returns**: Array of sensitive entities with their original and anonymized values

#### `clearEntityMapping(): void`

Clears the current entity mapping.

## Example

Input text:
```
Hello, my name is John Doe and my phone number is +1 555-123-4567.
```

Anonymized result:
```
Hello, my name is [PERSON] and my phone number is [PHONE].
```

Sensitive entities found:
```
[
  {
    "original": "John Doe",
    "anonymized": "[PERSON]",
    "entityType": "PERSON",
    "start": 18,
    "end": 26
  },
  {
    "original": "+1 555-123-4567",
    "anonymized": "[PHONE]",
    "entityType": "PHONE_NUMBER",
    "start": 46,
    "end": 61
  }
]
```

## License

This project is licensed under the MIT License - see the package.json file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.