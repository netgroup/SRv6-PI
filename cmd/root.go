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
	"context"
	"fmt"
	"os"

	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var globalOpts struct {
	Host string
	Port int
}

var client api.GobgpApiClient
var ctx context.Context
var cancel context.CancelFunc

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "goBGPSRv6PolicyClient",
	Short: "Inject SRv6 Policy with goBGP",
	Long: `Inject SRv6 Policy with goBGP. For example:
goBGPSRv6PolicyClient is a CLI ...`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var err error
		ctx = context.Background()
		client, cancel, err = newClient(ctx)
		if err != nil {
			cancel()
			fmt.Println(err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// if children declare their own, cancel is not called. Doesn't matter because the command will exit soon.
		if cancel != nil {
			cancel()
		}
	},
}

func newClient(ctx context.Context) (api.GobgpApiClient, func(), error) {
	target := fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port)
	conn, err := grpc.DialContext(context.TODO(), target, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("fail to connect to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
	client := api.NewGobgpApiClient(conn)
	// Testing connection to gobgp by requesting its global config
	if _, err := client.GetBgp(context.TODO(), &api.GetBgpRequest{}); err != nil {
		fmt.Printf("fail to get gobgp info with error: %+v\n", err)
		os.Exit(1)
	}
	return client, func() { conn.Close() }, nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVarP(&globalOpts.Host, "host", "u", "127.0.0.1", "host")
	rootCmd.PersistentFlags().IntVarP(&globalOpts.Port, "port", "p", 50051, "port")
	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.goBGPSRv6PolicyClient.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".goBGPSRv6PolicyClient" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".goBGPSRv6PolicyClient")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
