#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Plugin::Carbons',
	VERSION_FROM => 'lib/DJabberd/Plugin/Carbons.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Plugin/Carbons.pm',
	PREREQ_PM => {
		'DJabberd' => '0.86',
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
