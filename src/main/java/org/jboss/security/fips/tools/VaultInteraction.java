/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.security.fips.tools;

import java.io.Console;
import java.util.Scanner;

import org.jboss.security.vault.SecurityVault;

/**
 * Interaction with initialized {@link SecurityVault} via the {@link VaultTool}
 *
 * @author Anil Saldhana
 * @author Rich Lucente <rlucente_at_redhat_dot_com>
 */
public class VaultInteraction {

    private VaultSession vaultNISession;

    public VaultInteraction(VaultSession vaultSession) {
        this.vaultNISession = vaultSession;
    }

    public void start() {
        Console console = System.console();

        if (console == null) {
            System.err.println("No console.");
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        while (true) {
            String commandStr = "Please enter a Digit::  0: Store a secured attribute  1: Check whether a secured attribute exists  2: Remove secured attribute  3: Exit";

            System.out.println(commandStr);
            int choice = in.nextInt();
            switch (choice) {
                case 0:
                    System.out.println("Task: Store a secured attribute");
                    char[] attributeValue = VaultInteractiveSession.readSensitiveValue("secured attribute value (e.g. a password)");
                    String vaultBlock = null;

                    while (vaultBlock == null || vaultBlock.length() == 0) {
                        vaultBlock = console.readLine("Enter Vault Block: ");
                    }

                    String attributeName = null;

                    while (attributeName == null || attributeName.length() == 0) {
                        attributeName = console.readLine("Enter Attribute Name: ");
                    }
                    try {
                        vaultNISession.addSecuredAttributeWithDisplay(vaultBlock, attributeName, attributeValue);
                    } catch (Exception e) {
                        System.out.println("Problem occurred: " + e.getLocalizedMessage());
                    }
                    break;
                case 1:
                    System.out.println("Task: Verify whether a secured attribute exists");
                    try {
                        vaultBlock = null;

                        while (vaultBlock == null || vaultBlock.length() == 0) {
                            vaultBlock = console.readLine("Enter Vault Block: ");
                        }

                        attributeName = null;

                        while (attributeName == null || attributeName.length() == 0) {
                            attributeName = console.readLine("Enter Attribute Name: ");
                        }
                        if (!vaultNISession.checkSecuredAttribute(vaultBlock, attributeName))
                            System.out.println("No value has been store for (" + vaultBlock + ", " + attributeName + ")");
                        else
                            System.out.println("A value exists for (" + vaultBlock + ", " + attributeName + ")");
                    } catch (Exception e) {
                        System.out.println("Problem occurred: " + e.getLocalizedMessage());
                    }
                    break;
                case 2:
                    System.out.println("Task: Remove secured attribute");
                    try {
                        vaultBlock = null;

                        while (vaultBlock == null || vaultBlock.length() == 0) {
                            vaultBlock = console.readLine("Enter Vault Block: ");
                        }

                        attributeName = null;

                        while (attributeName == null || attributeName.length() == 0) {
                            attributeName = console.readLine("Enter Attribute Name: ");
                        }
                        if (!vaultNISession.removeSecuredAttribute(vaultBlock, attributeName)) {
                            System.out.println("Secured attribute " + VaultSession.blockAttributeDisplayFormat(vaultBlock, attributeName) + " was not removed from vault, check whether it exist");
                        } else {
                            System.out.println("Secured attribute " + VaultSession.blockAttributeDisplayFormat(vaultBlock, attributeName) + " has been successfuly removed from vault");
                        }
                    } catch (Exception e) {
                        System.out.println("Problem occurred: " + e.getLocalizedMessage());
                    }
                    break;
                default:
                    in.close();
                    System.exit(0);
            }
        }
    }
}