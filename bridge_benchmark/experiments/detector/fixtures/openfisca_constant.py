class aide_constante(Variable):
    def formula(famille, period, parameters):
        ressources = famille('ressources', period)
        return ressources <= 1000
