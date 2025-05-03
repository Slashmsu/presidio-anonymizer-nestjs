import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { catchError, firstValueFrom, retry, timer } from 'rxjs';
import { AxiosError } from 'axios';

export interface SensitiveEntity {
  original: string;
  anonymized: string;
  entityType: string;
  start: number;
  end: number;
}

@Injectable()
export class AnonymizerService {
  private readonly logger = new Logger(AnonymizerService.name);
  private entityMap: Map<string, SensitiveEntity> = new Map();
  
  constructor(
    private readonly http: HttpService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Analyzes text for sensitive information, anonymizes it, and maintains a mapping
   * for later deanonymization
   */
  async anonymizeText(text: string): Promise<{ anonymizedText: string; entitiesFound: boolean }> {
    try {
      // Clear previous entity mapping
      this.entityMap.clear();
      
      // Get URLs from config
      let analyzerUrl = this.configService.get<string>('PRESIDIO_ANALYZER_URL');
      let anonymizerUrl = this.configService.get<string>('PRESIDIO_ANONYMIZER_URL');

      // Add fallback URLs if environment variables are not set
      if (!analyzerUrl) {
        analyzerUrl = 'http://localhost:5001';
        this.logger.warn('PRESIDIO_ANALYZER_URL not set, using fallback: ' + analyzerUrl);
      }
      
      if (!anonymizerUrl) {
        anonymizerUrl = 'http://localhost:5002';
        this.logger.warn('PRESIDIO_ANONYMIZER_URL not set, using fallback: ' + anonymizerUrl);
      }
      
      // Check if URLs are swapped and fix them
      if (analyzerUrl.includes('5002') && anonymizerUrl.includes('5001')) {
        this.logger.warn('URLs appear to be swapped in environment variables, correcting them');
        const temp = analyzerUrl;
        analyzerUrl = anonymizerUrl;
        anonymizerUrl = temp;
      }

      this.logger.log(`Using analyzer URL: ${analyzerUrl}`);
      this.logger.log(`Using anonymizer URL: ${anonymizerUrl}`);

      // Step 1: Analyze the text to identify sensitive information
      try {
        const analyzerResponse = await this.analyzeText(text, analyzerUrl);
        const analyzerResults = analyzerResponse.data;
        
        // If no sensitive entities found, return the original text
        if (!analyzerResults || analyzerResults.length === 0) {
          return { anonymizedText: text, entitiesFound: false };
        }
        
        // Log analyzer results for debugging
        this.logger.log(`Analyzer found ${analyzerResults.length} entities: ${JSON.stringify(analyzerResults)}`);
        
        // Step 2: Anonymize the text based on analyze results
        const anonymizers = this.buildAnonymizersConfig();
        
        // Prepare anonymizer request
        const anonymizerResponse = await firstValueFrom(
          this.http.post(`${anonymizerUrl}/anonymize`, {
            text,
            anonymizers,
            analyzer_results: analyzerResults
          }, { timeout: 5000 }).pipe(
            retry({
              count: 2,
              delay: (error, retryCount) => {
                this.logger.log(`Retrying anonymizer request (${retryCount}/2)...`);
                return timer(1000);
              }
            }),
            catchError((error: AxiosError) => {
              this.logger.error(`Anonymizer service error: ${error.message}`, error.stack);
              throw new HttpException(
                'Failed to anonymize text',
                error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
              );
            })
          )
        );
        
        const anonymizedText = anonymizerResponse.data.text;
        const anonymizerResults = anonymizerResponse.data.items || [];
        
        // Log anonymizer results for debugging
        this.logger.log(`Anonymizer returned ${anonymizerResults.length} items: ${JSON.stringify(anonymizerResults)}`);
        
        // Step 3: Build entity mapping for deanonymization
        this.buildEntityMapping(text, anonymizerResults, analyzerResults);
        
        // Log the entityMap for debugging
        this.logger.log(`Entity map for deanonymization: ${JSON.stringify(Array.from(this.entityMap.values()))}`);
        
        this.logger.log(`Anonymized text: ${anonymizedText}`);
        this.logger.log(`Found ${this.entityMap.size} sensitive entities`);
        
        return { anonymizedText, entitiesFound: this.entityMap.size > 0 };
      } catch (error: any) {
        // If we can't anonymize, fall back to sending the text as-is
        this.logger.warn(`Failed to anonymize text: ${error.message}. Falling back to original text.`);
        return { anonymizedText: text, entitiesFound: false };
      }
    } catch (error: any) {
      this.logger.error(`Error anonymizing text: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Deanonymizes text by replacing anonymized values with original values
   */
  deanonymizeText(anonymizedText: string): string {
    if (this.entityMap.size === 0) {
      return anonymizedText; // No entities to deanonymize
    }
    
    let result = anonymizedText;
    
    // First, convert the entity map to an array and sort by anonymized string length (descending)
    // This ensures longer tokens are replaced first to avoid partial replacements
    const sortedEntities = Array.from(this.entityMap.values())
      .sort((a, b) => b.anonymized.length - a.anonymized.length);
    
    for (const entity of sortedEntities) {
      // Create a regex that can match the anonymized value precisely
      const escapedAnonymized = entity.anonymized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escapedAnonymized, 'g');
      
      // Replace all occurrences
      result = result.replace(regex, entity.original);
    }
    
    return result;
  }

  /**
   * Returns all sensitive entities found in the last anonymization
   */
  getSensitiveEntities(): SensitiveEntity[] {
    return Array.from(this.entityMap.values());
  }

  /**
   * Clear the entity mapping
   */
  clearEntityMapping(): void {
    this.entityMap.clear();
  }

  /**
   * Analyzes text to identify sensitive information
   */
  private async analyzeText(text: string, analyzerUrl: string) {
    const url = `${analyzerUrl}/analyze`;
    this.logger.log(`Sending analyzer request to: ${url}`);
    
    // Define all entity types supported by Presidio
    const entities = [
      "PERSON",
      "PHONE_NUMBER",
      "EMAIL_ADDRESS",
      "CREDIT_CARD",
      "DATE_TIME",
      "LOCATION",
      "NRP",
      "ORGANIZATION",
      "US_BANK_ACCOUNT",
      "US_DRIVER_LICENSE",
      "US_ITIN",
      "US_PASSPORT",
      "US_SSN",
      "UK_NHS",
      "IP_ADDRESS",
      "IBAN_CODE",
      "CRYPTO",
      "URL",
      "MEDICAL_LICENSE",
      "MEDICAL_RECORD",
      "AGE",
      "ADDRESS"
    ];
    
    // Configure threshold per entity type
    const threshold_dict = {
      // Lower threshold for phone numbers to catch more patterns
      "PHONE_NUMBER": 0.3,
      
      // Default threshold for other entities
      "DEFAULT": 0.5
    };
    
    return await firstValueFrom(
      this.http.post(url, {
        text,
        language: 'en',
        entities: entities,
        correlation_id: 'anonymization-request',
        allow_list: {
          "lower_case_name": "all",
          "language": "en",
          // An allowlist to help with recognizing certain patterns
          "patterns": [
            {
              "name": "phone-number-with-spaces",
              "regex": "\\+?\\d{1,3}\\s?\\d{2,3}\\s?\\d{5,8}",
              "score": 0.75,
              "entity_type": "PHONE_NUMBER"
            }
          ]
        },
        ad_hoc_recognizers: [
          {
            "name": "International Phone Number",
            "supported_language": "en",
            "patterns": [
              {
                "name": "phone-number-int",
                "regex": "\\+?(?:[0-9] ?){6,14}[0-9]",
                "score": 0.75
              }
            ],
            "context": ["contact", "phone", "call", "reach"],
            "supported_entity": "PHONE_NUMBER"
          }
        ],
        return_decision_process: true,
        threshold: 0.5,
        score_threshold: 0.5,
        threshold_dict: threshold_dict
      }, { timeout: 5000 }).pipe(
        retry({
          count: 2,
          delay: (error, retryCount) => {
            this.logger.log(`Retrying analyzer request (${retryCount}/2)...`);
            return timer(1000);
          }
        }),
        catchError((error: AxiosError) => {
          this.logger.error(`Analyzer service error: ${error.message}`, error.stack);
          if (error.code === 'ECONNREFUSED' || error.code === 'ECONNABORTED') {
            throw new HttpException(
              'Presidio Analyzer service is unavailable',
              HttpStatus.SERVICE_UNAVAILABLE
            );
          }
          throw new HttpException(
            'Failed to analyze text',
            error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
          );
        })
      )
    );
  }

  /**
   * Builds configuration for the anonymizer based on entity types
   */
  private buildAnonymizersConfig() {
    return {
      PHONE_NUMBER: {
        type: "replace",
        new_value: "[PHONE]"
      },
      NAME: {
        type: "replace",
        new_value: "[PERSON]"
      },
      PERSON: {
        type: "replace",
        new_value: "[PERSON]"
      },
      EMAIL_ADDRESS: {
        type: "mask",
        masking_char: "*",
        chars_to_mask: 5,
        from_end: false
      },
      LOCATION: {
        type: "replace",
        new_value: "[LOCATION]"
      },
      ORGANIZATION: {
        type: "replace",
        new_value: "[ORGANIZATION]" 
      },
      US_SSN: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 5,
        from_end: true
      },
      US_DRIVER_LICENSE: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 4,
        from_end: true
      },
      CREDIT_CARD: {
        type: "mask",
        masking_char: "*",
        chars_to_mask: 12,
        from_end: true
      },
      DATE_TIME: {
        type: "replace",
        new_value: "[DATE_TIME]"
      },
      NRP: {
        type: "replace",
        new_value: "[NRP]"
      },
      US_BANK_ACCOUNT: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 8,
        from_end: true
      },
      US_ITIN: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 5,
        from_end: true
      },
      US_PASSPORT: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 5,
        from_end: true
      },
      UK_NHS: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 6,
        from_end: true
      },
      IP_ADDRESS: {
        type: "mask",
        masking_char: "0",
        chars_to_mask: 6,
        from_end: true
      },
      IBAN_CODE: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 10,
        from_end: true
      },
      CRYPTO: {
        type: "mask",
        masking_char: "*",
        chars_to_mask: 10,
        from_end: true
      },
      URL: {
        type: "replace",
        new_value: "[URL]"
      },
      MEDICAL_LICENSE: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 5,
        from_end: true
      },
      MEDICAL_RECORD: {
        type: "mask",
        masking_char: "#",
        chars_to_mask: 5,
        from_end: true
      },
      AGE: {
        type: "replace",
        new_value: "[AGE]"
      },
      ADDRESS: {
        type: "replace",
        new_value: "[ADDRESS]"
      },
      // Default for other entity types
      DEFAULT: {
        type: "hash",
        hash_type: "sha256"
      }
    };
  }

  /**
   * Builds a mapping between original and anonymized entities
   */
  private buildEntityMapping(
    originalText: string,
    anonymizerResults: any[], 
    analyzerResults: any[]
  ): void {
    if (!anonymizerResults || anonymizerResults.length === 0) {
      return;
    }

    // Process and clean analyzer results - consolidate by entity type
    const entityMap = new Map<string, Array<any>>();
    
    // Group analyzer results by entity type
    for (const result of analyzerResults) {
      const entityType = result.entity_type;
      const entities = entityMap.get(entityType) || [];
      entities.push(result);
      entityMap.set(entityType, entities);
    }
    
    // For each entity type, find the best entity based on completeness
    const processedEntities = new Map<string, any>();
    for (const [entityType, entities] of entityMap.entries()) {
      // Sort by length (longer is likely more complete) and score
      entities.sort((a, b) => {
        const aLength = a.end - a.start;
        const bLength = b.end - b.start;
        if (aLength !== bLength) return bLength - aLength; // Prefer longer entities
        return b.score - a.score; // If same length, prefer higher score
      });
      
      // Process each entity with its unique position
      for (const entity of entities) {
        const key = `${entityType}-${entity.start}-${entity.end}`;
        if (!processedEntities.has(key)) {
          processedEntities.set(key, entity);
        }
      }
    }
    
    // Process anonymizer results
    const anonymizedEntities = new Map<string, string>();
    for (const result of anonymizerResults) {
      const entityType = result.entity_type;
      switch (entityType) {
        case 'PERSON':
          anonymizedEntities.set(entityType, '[PERSON]');
          break;
        case 'PHONE_NUMBER':
          anonymizedEntities.set(entityType, '[PHONE]');
          break;
        case 'DATE_TIME':
          anonymizedEntities.set(entityType, '[DATE_TIME]');
          break;
        case 'ORGANIZATION':
          anonymizedEntities.set(entityType, '[ORGANIZATION]');
          break;
        case 'LOCATION':
          anonymizedEntities.set(entityType, '[LOCATION]');
          break;
        default:
          anonymizedEntities.set(entityType, result.text || `[${entityType}]`);
      }
    }
    
    // Now construct the final entity map for deanonymization
    for (const entity of processedEntities.values()) {
      const entityType = entity.entity_type;
      const start = entity.start;
      const end = entity.end;
      
      // Extract the original value from the text
      const originalValue = originalText.substring(start, end);
      
      // Get the standardized anonymized value
      const anonymizedValue = anonymizedEntities.get(entityType) || `[${entityType}]`;
      
      // Skip entities that are likely fragments
      if (entityType === 'PERSON' && originalValue.length < 3) {
        continue;
      }
      
      // Create a unique key for this entity
      const key = `${entityType}-${start}-${end}`;
      
      this.entityMap.set(key, {
        original: originalValue,
        anonymized: anonymizedValue,
        entityType,
        start,
        end
      });
      
      this.logger.log(`Added clean entity mapping: ${originalValue} -> ${anonymizedValue}`);
    }
    
    // For specific entity types, ensure we have the best match
    this.findBestMatch(originalText, 'PHONE_NUMBER');
    this.findBestMatch(originalText, 'PERSON');
  }
  
  /**
   * Finds the best match for a given entity type from all detected entities
   */
  private findBestMatch(originalText: string, entityType: string): void {
    // Filter entities by the given type
    const entities = Array.from(this.entityMap.values())
      .filter(e => e.entityType === entityType);
    
    if (entities.length <= 1) {
      return; // No need to find best match if there's only one or none
    }
    
    // For PHONE_NUMBER, prefer the one with + sign or longest
    if (entityType === 'PHONE_NUMBER') {
      // Sort by completeness metrics
      entities.sort((a, b) => {
        // Prefer ones with + sign
        const aHasPlus = a.original.includes('+');
        const bHasPlus = b.original.includes('+');
        if (aHasPlus !== bHasPlus) return bHasPlus ? 1 : -1;
        
        // Then by length
        return b.original.length - a.original.length;
      });
      
      // Keep only the best match
      const bestMatch = entities[0];
      
      // Clear all entities of this type
      Array.from(this.entityMap.keys())
        .filter(key => key.startsWith(`${entityType}-`))
        .forEach(key => this.entityMap.delete(key));
      
      // Add back only the best match
      this.entityMap.set(`${entityType}-best`, {
        original: bestMatch.original,
        anonymized: bestMatch.anonymized,
        entityType,
        start: bestMatch.start,
        end: bestMatch.end
      });
      
      this.logger.log(`Selected best phone: ${bestMatch.original} -> ${bestMatch.anonymized}`);
    }
    
    // For PERSON, prefer the one that looks most like a full name
    if (entityType === 'PERSON') {
      // Sort by completeness metrics
      entities.sort((a, b) => {
        // Prefer ones with space (likely first + last name)
        const aHasSpace = a.original.includes(' ');
        const bHasSpace = b.original.includes(' ');
        if (aHasSpace !== bHasSpace) return bHasSpace ? 1 : -1;
        
        // Then by length
        return b.original.length - a.original.length;
      });
      
      // Keep only the best match
      const bestMatch = entities[0];
      
      // Clear all entities of this type
      Array.from(this.entityMap.keys())
        .filter(key => key.startsWith(`${entityType}-`))
        .forEach(key => this.entityMap.delete(key));
      
      // Add back only the best match
      this.entityMap.set(`${entityType}-best`, {
        original: bestMatch.original,
        anonymized: bestMatch.anonymized,
        entityType,
        start: bestMatch.start,
        end: bestMatch.end
      });
      
      this.logger.log(`Selected best person: ${bestMatch.original} -> ${bestMatch.anonymized}`);
    }
  }
}
