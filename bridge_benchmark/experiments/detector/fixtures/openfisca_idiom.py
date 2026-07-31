class plafond_eligibilite(Variable):
    def formula(famille, period, parameters):
        zone_logement = famille('zone_logement', period)
        seuils = parameters(period).aide.plafond_ressources_par_zone[zone_logement]
        ressources = famille('ressources', period)
        return ressources <= seuils
