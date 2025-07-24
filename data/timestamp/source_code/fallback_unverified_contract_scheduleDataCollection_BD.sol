/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleDataCollection
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability exploits timestamp dependence in a multi-transaction sequence. An attacker (miner) can manipulate block timestamps to: 1) Control when scheduled data collection executes, 2) Influence power reading calculations based on timestamp parity, 3) Bypass interval restrictions by timestamp manipulation. The vulnerability requires multiple transactions: first to schedule collection, then to execute it, with state persisting between calls.
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Scheduling mechanism for automated data collection
    struct DataCollectionSchedule {
        uint256 scheduledTime;
        uint256 collectionInterval;
        address targetLink;
        bool active;
        uint256 lastExecution;
    }
    
    mapping(address => DataCollectionSchedule) public schedules;
    
    function scheduleDataCollection(address link, uint256 timeFromNow, uint256 interval) {
        if(timeFromNow < 60) throw; // Minimum 1 minute delay
        
        DataCollectionSchedule storage schedule = schedules[msg.sender];
        schedule.scheduledTime = now + timeFromNow;
        schedule.collectionInterval = interval;
        schedule.targetLink = link;
        schedule.active = true;
        schedule.lastExecution = 0;
    }
    
    function executeScheduledCollection() {
        DataCollectionSchedule storage schedule = schedules[msg.sender];
        
        if(!schedule.active) throw;
        
        // Vulnerable timestamp dependence - miners can manipulate 'now'
        // to trigger execution at favorable times
        if(now < schedule.scheduledTime) throw;
        
        // Check if enough time has passed since last execution
        if(schedule.lastExecution > 0 && (now - schedule.lastExecution) < schedule.collectionInterval) {
            throw;
        }
        
        // Execute the collection - this creates exploitable timing windows
        ZS storage zs = zss[schedule.targetLink];
        
        // Vulnerable: Different behavior based on timestamp
        if(now % 2 == 0) {
            // Even timestamps get bonus power readings
            zs.power_in += 100;
            zs.power_out += 100;
        }
        
        zs.time = now;
        schedule.lastExecution = now;
        
        // Vulnerability: Miners can manipulate when this gets executed
        // by controlling block timestamps, affecting power calculations
        pinged(schedule.targetLink, zs.time, zs.power_in, zs.power_out);
    }
    // === END FALLBACK INJECTION ===

    
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
