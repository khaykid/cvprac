    self.creds = {
            line.strip().split("=")[0]: line.strip().split("=")[1] for line in lines
        }