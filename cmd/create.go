/*
Copyright © 2021 Francesco Lombardo <franclombardo@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
)

var policyFile string

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create SRv6 Policy Path",
	Long: `Create SRv6 Policy Path defined in a YAML file. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create called")

		srv6policypathFromFile := SRv6PolicyPath{}
		srv6policypathFromFile.fromFile(policyFile)
		spp_path, err := srv6policypathFromFile.toPath()
		client.AddPath(ctx, &api.AddPathRequest{
			TableType: api.TableType_GLOBAL,
			Path:      spp_path,
		})

		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("path created")
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	createCmd.PersistentFlags().StringVar(&policyFile, "policyFile", "policyFile.yaml", "policy file (default is ~/policyFile.yaml)")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
