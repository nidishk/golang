package controllers

import (
	"github.com/revel/revel"
)

type Errors struct {
	*revel.Controller
}


type NotFoundResponse struct {
    Code int `json:"code"`
    Message string `json:"message"`
}

func (c Errors) NotFound() revel.Result {
    data := NotFoundResponse{Code: 404, Message: "Found Nothing"}
    c.Response.Status = 404
    return c.RenderJSON(data)
}
