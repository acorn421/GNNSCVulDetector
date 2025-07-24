/*
 * ===== SmartInject Injection Details =====
 * Function      : ping
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the oracle's validateReading function before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls ping() with a malicious contract as the oracle address for a new link. The ZS struct is initialized with the attacker's contract as the oracle.
 * 
 * 2. **Transaction 2 (Reentrancy Attack)**: Attacker calls ping() again for the same link. The function makes an external call to the attacker's malicious oracle contract for validation. During this call, the attacker's contract re-enters the ping() function multiple times before the original state updates complete.
 * 
 * 3. **State Manipulation**: During reentrancy, the attacker can:
 *    - Manipulate power readings by calling ping() with different delta values
 *    - Accumulate power_in/power_out values beyond intended limits
 *    - Modify oracle assignments for other links
 *    - Create inconsistent state between what's validated and what's recorded
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **Oracle Setup Phase**: The oracle address must be established in a previous transaction (zs.time==0 condition)
 * - **Persistent State Dependency**: The vulnerability depends on the oracle address being stored in the zss mapping from prior transactions
 * - **Accumulated State Changes**: Each reentrant call accumulates power values and time, creating compound effects across multiple calls
 * - **Authorization Bypass**: The oracle authorization check (zs.oracle==msg.sender) relies on state set in previous transactions
 * 
 * The vulnerability is realistic because oracle validation is a common pattern in smart meter systems, and the external call placement before state updates follows a common anti-pattern that creates reentrancy opportunities.
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
         ZS storage zs = zss[link];
         zs.oracle=oracle;
         zs.time=now;
         zs.power_in=_power_in;
         zs.power_out=_power_out;
         zss[link]=zs;
        
    }

    function ping(address link,uint256 delta_time,uint256 delta_power_in,uint256 delta_power_out) public {
        ClearanceLimits memory limits = defaultLimits;
        if(!limits.valid) {  throw; }
        if((limits.min_power>delta_power_in)&&(limits.min_power>delta_power_out) ) throw;
        if((limits.max_power<delta_power_in)&&(limits.max_power<delta_power_out)) throw;
        if(limits.min_time>delta_time) throw;
        if(limits.max_time<delta_time) throw;
        
        ZS storage zs = zss[link];
        
        if(zs.time==0) {
            zs.oracle=msg.sender;
            zs.time=now;
        } else {
            if((zs.oracle!=msg.sender) &&(zs.oracle!=owner)) throw;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Oracle validation callback - potentially allows reentrancy
        if(zs.oracle != address(0) && zs.oracle != owner) {
            // External call to oracle for validation before state update
            bool success = zs.oracle.call(bytes4(keccak256("validateReading(address,uint256,uint256,uint256)")), link, delta_time, delta_power_in, delta_power_out);
            if(!success) throw;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        zs.time+=delta_time;
        zs.power_in+=delta_power_in;
        zs.power_out+=delta_power_out;
        zss[link]=zs;
        pinged(link,zs.time,zs.power_in,zs.power_out);
    }
}