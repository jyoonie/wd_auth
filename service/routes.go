package service

func (s *Service) registerRoutes() {
	s.r.GET("/ping", s.Ping)

	s.r.GET("/", s.Homepage)

	s.r.POST("/login", s.Login)

	s.r.POST("/users", s.CreateUser)

	s.r.POST("/ingredients/search", s.SearchIngredients)

	authorized := s.r.Group("/")
	authorized.Use(s.ValidateToken)
	{
		authorized.GET("/users/:id", s.GetUser)
		authorized.POST("/users/:id", s.UpdateUser)

		authorized.GET("/ingredients/:id", s.GetIngredient)
		authorized.POST("/ingredients", s.CreateIngredient)
		authorized.POST("/ingredients/:id", s.UpdateIngredient)
		authorized.DELETE("/ingredients/:id", s.DeleteIngredient)

		authorized.GET("/users/:id/fridge_ingredients", s.ListFridgeIngredients)
		authorized.POST("/fridge_ingredients", s.CreateFridgeIngredient)
		authorized.POST("/fridge_ingredients/:id", s.UpdateFridgeIngredient)
		authorized.DELETE("/users/:uid/fridge_ingredients/:iid", s.DeleteFridgeIngredient)

		authorized.GET("/recipes/:id", s.GetRecipe)
		authorized.GET("/users/:id/recipes", s.ListRecipes)
		authorized.POST("/recipes/search", s.SearchRecipes)
		authorized.POST("/recipes", s.CreateRecipe)
		authorized.POST("/recipes/:id", s.UpdateRecipe)
		authorized.DELETE("/recipes/:id", s.DeleteRecipe)
	}
}
