"""bulkupload module forms.py."""
# Third-Party Libraries
from django import forms
from django.core.exceptions import ValidationError


class CSVUploadForm(forms.Form):
    """CSVUploadForm class."""

    file = forms.FileField()

    def clean(self):
        """Clean function."""
        cleaned_data = super().clean()
        file = cleaned_data.get("file")
        if not file.name.endswith(".csv"):
            raise ValidationError(
                {
                    "file": "Filetype not supported, the file must be a '.csv'",
                }
            )
        return cleaned_data
