/*
 * ===== SmartInject Injection Details =====
 * Function      : changeZS
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based oracle validation logic that relies on block.timestamp differences between consecutive function calls. The vulnerability accumulates trust scores in persistent state based on timing intervals, creating a multi-transaction exploit scenario where miners can manipulate block timestamps to influence power readings and oracle trust calculations across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added time-based validation logic that compares current `now` with previously stored `zs.time`
 * 2. Implemented accumulative trust scoring that modifies power readings based on timestamp intervals
 * 3. Created stateful penalty/reward system that persists between transactions
 * 4. The vulnerability requires multiple changeZS calls to build up exploitable state
 * 
 * **Multi-Transaction Exploitation Path:**
 * - Transaction 1: Owner calls changeZS() establishing initial timestamp baseline
 * - Transaction 2: Miner manipulates block.timestamp to create favorable time differences  
 * - Transaction 3: Owner calls changeZS() again, triggering time-based logic with manipulated timestamps
 * - The accumulated state changes enable power reading manipulation across the transaction sequence
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on comparing timestamps between different function calls
 * - State accumulation (power adjustments) builds up over multiple transactions
 * - Single transaction cannot exploit the time difference logic as it requires prior state
 * - The trust scoring system requires historical timestamp data from previous calls
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

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
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
    
    function changeClearance(uint256 _min_time,uint256 _min_power,uint256 _max_time, uint256 _max_power,bool _clearance) onlyOwner {
        defaultLimits = ClearanceLimits(_min_time,_min_power,_max_time,_max_power,msg.sender,_clearance);
    }
    

    function changeZS(address link,address oracle,uint256 _power_in,uint256 _power_out) onlyOwner {
         ZS zs = zss[link];
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
         
         // Vulnerability: Time-based oracle validation with accumulated state
         if(zs.time > 0) {
             // Use block.timestamp difference for oracle trust validation
             uint256 timeDiff = now - zs.time;
             
             // Accumulate trust score based on timestamp intervals
             // This creates stateful vulnerability across multiple transactions
             if(timeDiff < 300) { // Less than 5 minutes = suspicious
                 // Store suspicious timing pattern for future validation
                 zs.power_in = (zs.power_in * 90) / 100; // Reduce by 10% as penalty
             } else if(timeDiff > 3600) { // More than 1 hour = trusted
                 // Reward consistent timing with power boost
                 zs.power_in = (zs.power_in * 110) / 100; // Increase by 10% as bonus
             }
         }
         
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
         zs.oracle=oracle;
         zs.time=now;
         zs.power_in=_power_in;
         zs.power_out=_power_out;
         zss[link]=zs;
        
    }  
    function ping(address link,uint256 delta_time,uint256 delta_power_in,uint256 delta_power_out) {
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
