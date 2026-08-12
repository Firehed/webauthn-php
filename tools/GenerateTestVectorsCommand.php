<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Tools;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

use function count;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function is_dir;
use function is_file;
use function is_string;
use function mkdir;
use function sprintf;

#[AsCommand(
    name: 'generate-test-vectors',
    description: 'Regenerate the W3C integration fixtures from a WebAuthn spec checkout',
)]
class GenerateTestVectorsCommand extends Command
{
    private const DEFAULT_OUTPUT = __DIR__ . '/../tests/integration';

    protected function configure(): void
    {
        $this
            ->addOption(
                'spec',
                's',
                InputOption::VALUE_REQUIRED,
                'Path to index.bs from a w3c/webauthn checkout',
            )
            ->addOption(
                'output',
                'o',
                InputOption::VALUE_REQUIRED,
                'Directory to write vector directories into',
                self::DEFAULT_OUTPUT,
            )
            ->addOption(
                'prefix',
                null,
                InputOption::VALUE_REQUIRED,
                'Prefix applied to each vector directory name',
                'w3c-',
            )
            ->addOption(
                'check',
                null,
                InputOption::VALUE_NONE,
                'Report differences without writing, exiting non-zero if any are found',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $specPath = $input->getOption('spec');
        if (!is_string($specPath)) {
            $io->error('--spec is required; point it at index.bs in a w3c/webauthn checkout.');
            return Command::INVALID;
        }
        $spec = @file_get_contents($specPath);
        if ($spec === false) {
            $io->error(sprintf('Could not read %s', $specPath));
            return Command::INVALID;
        }

        $outputDir = $input->getOption('output');
        $prefix = $input->getOption('prefix');
        if (!is_string($outputDir) || !is_string($prefix)) {
            $io->error('--output and --prefix must be strings.');
            return Command::INVALID;
        }
        $check = $input->getOption('check') === true;

        $vectors = (new SpecParser())->parse($spec);
        $writer = new FixtureWriter();

        $changed = [];
        foreach ($vectors as $vector) {
            $dir = sprintf('%s/%s%s', $outputDir, $prefix, $vector->slug);
            foreach ($writer->render($vector) as $name => $contents) {
                $path = sprintf('%s/%s', $dir, $name);
                if (is_file($path) && file_get_contents($path) === $contents) {
                    continue;
                }
                $changed[] = $path;
                if (!$check) {
                    self::write($path, $contents);
                }
            }
        }

        $io->text(sprintf('Parsed %d vectors from %s', count($vectors), $specPath));

        if ($changed === []) {
            $io->success('Fixtures are up to date.');
            return Command::SUCCESS;
        }

        $io->listing($changed);
        if ($check) {
            $io->error(sprintf('%d file(s) differ from the generated output.', count($changed)));
            return Command::FAILURE;
        }
        $io->success(sprintf('Wrote %d file(s).', count($changed)));
        return Command::SUCCESS;
    }

    private static function write(string $path, string $contents): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, recursive: true);
        }
        file_put_contents($path, $contents);
    }
}
