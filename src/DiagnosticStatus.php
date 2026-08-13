<?php

declare(strict_types=1);

namespace BastionSecurityWP;

enum DiagnosticStatus: string
{
    case Good = 'good';
    case Recommended = 'recommended';
    case Critical = 'critical';
    case NotAssessed = 'not_assessed';
}
