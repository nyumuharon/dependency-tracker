package main

import (
	"github.com/nyumuharon/dependency-tracker/internal/report"
)

type SARIFReport = report.SARIFReport
type CycloneDXSBOM = report.CycloneDXSBOM

func PrintReport(results []ScanResult) {
	report.PrintReport(results)
}

func GenerateSBOM(results []ScanResult, outputPath string) error {
	return report.GenerateSBOM(results, outputPath, appVersion)
}

func GenerateSARIF(results []ScanResult, outputPath string) error {
	return report.GenerateSARIF(results, outputPath, appVersion)
}

func generateSARIFWithDirectory(results []ScanResult, outputPath string, workingDirectory func() (string, error)) error {
	return report.GenerateSARIFWithDirectory(results, outputPath, appVersion, workingDirectory)
}

func Score(cvss, epss float64, hasCVE, isKEV bool) string {
	return report.Score(cvss, epss, hasCVE, isKEV)
}

func ScoreVulnerabilities(vulns []Vulnerability) string {
	return report.ScoreVulnerabilities(vulns)
}

func buildPURL(pkg Package) string {
	return report.BuildPURL(pkg)
}
