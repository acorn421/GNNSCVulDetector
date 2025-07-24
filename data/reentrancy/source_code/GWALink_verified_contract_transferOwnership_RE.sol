/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner before updating the owner state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` with `onOwnershipTransferred(address)` selector
 * 2. Used try-catch for backward compatibility (realistic production pattern)
 * 3. Moved the state change (`owner = newOwner`) to occur AFTER the external call
 * 4. Added null check for newOwner address (defensive programming pattern)
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` where maliciousContract implements fallback/receive
 * 2. **During external call**: The malicious contract's fallback function re-enters the contract
 * 3. **Reentrancy window**: Since `owner` hasn't been updated yet, the attacker still passes the `onlyOwner` check
 * 4. **Transaction 2**: Attacker can call `transferOwnership` again or other owner-only functions
 * 5. **State persistence**: The ownership state changes persist between transactions, creating lasting impact
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the timing window between the external call and state update
 * - Multiple function calls are needed to fully exploit the inconsistent ownership state
 * - The attacker needs separate transactions to set up the malicious contract and trigger the vulnerability
 * - The exploit requires accumulated state changes across multiple calls to be effective
 * 
 * **Realistic Production Context:**
 * - Owner notification callbacks are common in ownership transfer patterns
 * - The try-catch pattern makes it appear like defensive programming
 * - External calls for logging/registry updates fit naturally in this context
 * - The vulnerability would appear as legitimate functionality to code reviewers
 */
pragma solidity ^0.4.10;
/**
 * Smart Meter Gatway Aministration for StromDAO Stromkonto
 * ====================================================================
 * Slot-Link für intelligente Messsysteme zur Freigabe einer Orakel-gesteuerten
 * Zählrestandsgang-Messung. Wird verwendet zur Emulierung eines autarken 
 * Lieferanten/Abnehmer Managements in einem HSM oder P2P Markt ohne zentrale
 * Kontrollstelle.
 * 
 * Kontakt V0.1.1: 
 * Thorsten Zoerner <thorsten.zoerner(at)stromdao.de)
 * https://stromdao.de/
 */

contract owned {
     address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the new owner before transferring ownership
        // This allows the new owner to prepare for ownership transfer
        if (newOwner != address(0)) {
            // External call to notify new owner - vulnerable to reentrancy
            /* solhint-disable-next-line avoid-call-value, avoid-low-level-calls */
            if (!newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
                // Call failed, but continue anyway for backward compatibility
            }
        }
        // State change happens after external call - VULNERABLE
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = newOwner;
    }
}

contract GWALink is owned {
    uint80 constant None = uint80(0); 
    
    // Freigaben für einzelne Nodes
    struct ClearanceLimits {
        uint256 min_time;
        uint256 min_power;
        uint256 max_time;
        uint256 max_power;
        address definedBy;
        bool valid;
    }
    
    // Representation eines Zählerstandes
    struct ZS {
        uint256 time;
        uint256 power_in;
        uint256 power_out;
        address oracle;
    }
    
    event recleared(address link);
    event pinged(address link,uint256 time,uint256 power_in,uint256 power_out);
    
    ClearanceLimits public defaultLimits = ClearanceLimits(1,1,86400,1000,owner,true);
  
    mapping(address=>ZS) public zss;
    
    function changeClearance(uint256 _min_time,uint256 _min_power,uint256 _max_time, uint256 _max_power,bool _clearance) onlyOwner public {
        defaultLimits = ClearanceLimits(_min_time,_min_power,_max_time,_max_power,msg.sender,_clearance);
    }
    

    
    function changeZS(address link,address oracle,uint256 _power_in,uint256 _power_out) onlyOwner public {
         ZS zs = zss[link];
         zs.oracle=oracle;
         zs.time=now;
         zs.power_in=_power_in;
         zs.power_out=_power_out;
         zss[link]=zs;
        
    }

    
    function ping(address link,uint256 delta_time,uint256 delta_power_in,uint256 delta_power_out) public {
        ClearanceLimits  limits = defaultLimits;
        if(!limits.valid) {  throw; }
        if((limits.min_power>delta_power_in)&&(limits.min_power>delta_power_out) ) throw;
        if((limits.max_power<delta_power_in)&&(limits.max_power<delta_power_out)) throw;
        if(limits.min_time>delta_time) throw;
        if(limits.max_time<delta_time) throw;
        
        ZS zs = zss[link];
        
        if(zs.time==0) {
            zs.oracle=msg.sender;
            zs.time=now;
        } else {
            if((zs.oracle!=msg.sender) &&(zs.oracle!=owner)) throw;
        }
        
        zs.time+=delta_time;
        zs.power_in+=delta_power_in;
        zs.power_out+=delta_power_out;
        zss[link]=zs;
        pinged(link,zs.time,zs.power_in,zs.power_out);
    }
}