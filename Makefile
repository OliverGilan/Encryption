all:
	@echo run make zip to create a zip file for submission

zip:
	echo creating $(LOGNAME)-p3.zip
	@ zip $(LOGNAME)-p3.zip hidefile/hidefile.c unexpire/newtime.c

