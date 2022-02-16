package net

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SetupFirewall Linux", func() {
	FWhen("MBUS Url is bad", func() {
		Context("throws a nice error", func() {
			It("mbus url cannot be parsed due to bad scheme", func() {
				err := SetupNatsFirewall("nats:/user:pass@host.local:1234")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("Error parsing MbusURL"))
			})
			It("mbus url cannot be parsed for the nats port", func() {
				err := SetupNatsFirewall("nats://user:pass@host.local")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("missing port in address"))
			})
			It("Creates the rule even if is only partial auth data", func() {
				err := SetupNatsFirewall("nats://user@host.local:1234")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("missing port in address"))
			})
		})
	})
})
