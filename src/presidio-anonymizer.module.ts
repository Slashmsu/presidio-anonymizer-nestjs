import { DynamicModule, Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { AnonymizerService } from './anonymizer.service';

export interface PresidioOptions {
  analyzerUrl: string;
  anonymizerUrl: string;
}

export const PRESIDIO_OPTS = 'PRESIDIO_OPTS';

@Module({})
export class PresidioAnonymizerModule {
  static forRoot(options: PresidioOptions): DynamicModule {
    return {
      module: PresidioAnonymizerModule,
      imports: [HttpModule, ConfigModule],
      providers: [
        AnonymizerService,
        { provide: PRESIDIO_OPTS, useValue: options },
      ],
      exports: [AnonymizerService],
    };
  }
}