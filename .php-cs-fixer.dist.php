<?php

$header = <<<'EOF'
This file is part of Swoole.

@link     https://www.swoole.com
@contact  team@swoole.com
@license  https://github.com/swoole/library/blob/master/LICENSE
EOF;

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@DoctrineAnnotation'                              => true,
        '@PhpCsFixer'                                      => true,
        '@PSR2'                                            => true,
        '@Symfony'                                         => true,
        'align_multiline_comment'                          => ['comment_type' => 'all_multiline'],
        'array_syntax'                                     => ['syntax' => 'short'],
        'binary_operator_spaces'                           => ['operators' => ['=' => 'align', '=>' => 'align', ]],
        'blank_line_after_namespace'                       => true,
        'blank_line_before_statement'                      => ['statements' => ['declare']],
        'class_attributes_separation'                      => true,
        'concat_space'                                     => ['spacing' => 'one'],
        'constant_case'                                    => ['case' => 'lower'],
        'combine_consecutive_unsets'                       => true,
        'declare_strict_types'                             => true,
        'fully_qualified_strict_types'                     => ['phpdoc_tags' => []],
        'general_phpdoc_annotation_remove'                 => ['annotations' => ['author']],
        'header_comment'                                   => ['comment_type' => 'PHPDoc', 'header' => $header, 'location' => 'after_open', 'separate' => 'bottom'],
        'increment_style'                                  => ['style' => 'post'],
        'lambda_not_used_import'                           => false,
        'linebreak_after_opening_tag'                      => true,
        'list_syntax'                                      => ['syntax' => 'short'],
        'lowercase_static_reference'                       => true,
        'multiline_comment_opening_closing'                => true,
        'multiline_whitespace_before_semicolons'           => ['strategy' => 'new_line_for_chained_calls'],
        'no_superfluous_phpdoc_tags'                       => ['allow_mixed' => true, 'allow_unused_params' => true, 'remove_inheritdoc' => false],
        'no_unused_imports'                                => true,
        'no_useless_else'                                  => true,
        'no_useless_return'                                => true,
        'not_operator_with_space'                          => false,
        'not_operator_with_successor_space'                => false,
        'php_unit_strict'                                  => false,
        'phpdoc_align'                                     => ['align' => 'left'],
        'phpdoc_annotation_without_dot'                    => false,
        'phpdoc_no_empty_return'                           => false,
        'phpdoc_types_order'                               => ['sort_algorithm' => 'none', 'null_adjustment' => 'always_last'],
        'phpdoc_separation'                                => false,
        'phpdoc_summary'                                   => false,
        'ordered_class_elements'                           => true,
        'ordered_imports'                                  => ['imports_order' => ['class', 'function', 'const'], 'sort_algorithm' => 'alpha'],
        'ordered_types'                                    => ['null_adjustment' => 'always_last', 'sort_algorithm' => 'none'],
        'single_line_comment_style'                        => ['comment_types' => []],
        'single_line_comment_spacing'                      => false,
        'single_line_empty_body'                           => false,
        'single_quote'                                     => true,
        'standardize_increment'                            => false,
        'standardize_not_equals'                           => true,
        'yoda_style'                                       => ['always_move_variable' => false, 'equal' => false, 'identical' => false],
    ])
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->exclude(['html', 'vendor'])
            ->in(__DIR__)
    )
    ->setUsingCache(false);
