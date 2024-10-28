package plugin

const (
	DecodedQueryField string = "decodedQuery"
	DetectorField     string = "detector"
	QueryField        string = "query"
	ErrorField        string = "error"
	IsInjectionField  string = "is_injection"
	ResponseField     string = "response"
	ConfidenceField   string = "confidence"
	TokensField       string = "tokens"
	StringField       string = "String"
	ResponseTypeField string = "response_type"

	DeepLearningModel string = "deep_learning_model"
	Libinjection      string = "libinjection"

	ResponseType  string = "error"
	ErrorSeverity string = "EXCEPTION"
	ErrorNumber   string = "42000"
	ErrorMessage  string = "SQL injection detected"
	ErrorDetail   string = "Back off, you're not welcome here."
	LogLevel      string = "error"

	PredictPath string = "/predict"
)
