/*
 * ===== SmartInject Injection Details =====
 * Function      : genNumber
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
 * **VULNERABILITY INJECTION SUMMARY:**
 * 
 * **1. Specific Changes Made:**
 * - Added timestamp-dependent bonus calculation that accumulates based on time differences between calls
 * - Introduced timestamp-based seed values (timestampSeed and blockSeed) that influence random number generation
 * - Created conditional logic that provides predictable high/low outcomes based on timestamp patterns
 * - Applied time-based multipliers to the random number generation
 * 
 * **2. Multi-Transaction Exploitation Method:**
 * - **Phase 1**: Attacker calls genNumber() to establish initial _time state
 * - **Phase 2**: Attacker waits for favorable timestamp conditions where (block.timestamp % 1000) > 800 AND (block.number % 100) > 80
 * - **Phase 3**: Miner can manipulate timestamp within ~15 second tolerance to hit the favorable condition
 * - **Phase 4**: Second call to genNumber() exploits both the accumulated timeBonus and the predictable timestamp-based enhancement
 * 
 * **3. Why Multi-Transaction Requirement:**
 * - **State Dependency**: The timeBonus calculation requires a previous _time value to be set (first transaction establishes this)
 * - **Accumulation Effect**: The bonus increases based on time elapsed between calls, requiring temporal separation
 * - **Predictable Patterns**: Attackers need to observe timestamp patterns across multiple blocks to time their exploitation
 * - **Miner Collaboration**: Miners can coordinate across multiple blocks to ensure favorable timestamp conditions are met
 * 
 * **4. Exploitation Scenarios:**
 * - **Scenario A**: Call function when timestamp % 1000 > 800 for guaranteed 1.5x-6x multiplier on random number
 * - **Scenario B**: Strategic timing to maximize timeBonus accumulation combined with favorable timestamp seeds
 * - **Scenario C**: Miner front-running by manipulating block.timestamp to create predictable high-value outcomes
 * 
 * **5. Vulnerability Characteristics:**
 * - **Stateful**: Requires _time state from previous transaction
 * - **Multi-Transaction**: Cannot be exploited in single atomic transaction
 * - **Timestamp Dependent**: Relies on block.timestamp and block.number manipulation
 * - **Realistic**: Mimics real-world bonus/reward systems that use timing mechanisms
 */
pragma solidity ^0.4.24;

library SafeMath {
    function add(uint256 a, uint256 b)
        internal
        pure
        returns (uint256 c) 
    {
        c = a + b;
        require(c >= a, "SafeMath add failed");
        return c;
    }
}

contract RandomNumber {
	using SafeMath for *;

	address _owner;
	uint24 private _number;
	uint256 private _time;
	uint256 private _timespan;
    event onNewNumber
    (
        uint24 number,
        uint256 time
    );
	
	constructor(uint256 timespan) 
		public 
	{
		_owner = msg.sender;
		_time = 0;
		_number = 0;
		_timespan = timespan;
	}

	function number() 
		public 
		view 
		returns (uint24) 
	{
		return _number;
	}

	function time() 
		public 
		view 
		returns (uint256) 
	{
		return _time;
	}

	function timespan() 
		public 
		view 
		returns (uint256) 
	{
		return _timespan;
	}

	function genNumber() 
		public 
	{
		require(block.timestamp > _time + _timespan);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Timestamp-dependent bonus calculation that accumulates over time
		uint256 timeBonus = 0;
		if (_time > 0) {
			uint256 timeDiff = block.timestamp - _time;
			// Vulnerable: bonus based on timestamp difference can be manipulated
			timeBonus = (timeDiff * 100) / _timespan;
			if (timeBonus > 500) timeBonus = 500; // Cap at 500%
		}
		
		_time = block.timestamp;
		
		// Store timestamp-dependent state for future use
		uint256 timestampSeed = block.timestamp % 1000;
		uint256 blockSeed = block.number % 100;
		
		// Multi-transaction vulnerability: use accumulated timestamp patterns
		uint256 enhancedRandom = random();
		if (timestampSeed > 800 && blockSeed > 80) {
			// Vulnerable: predictable high-value outcome based on timestamp
			enhancedRandom = (enhancedRandom * (100 + timeBonus)) / 100;
		} else if (timestampSeed < 200 && blockSeed < 20) {
			// Vulnerable: predictable low-value outcome based on timestamp
			enhancedRandom = (enhancedRandom * 50) / 100;
		} else {
			// Apply time-based bonus to normal random outcome
			enhancedRandom = (enhancedRandom * (100 + timeBonus)) / 100;
		}
		
		_number = uint24(enhancedRandom % 1000000);
		
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		emit RandomNumber.onNewNumber (
			_number,
			_time
		);
	}

    function random() 
    	private 
    	view 
    	returns (uint24)
    {
        uint256 randnum = uint256(keccak256(abi.encodePacked(
            
            (block.timestamp).add
            (block.difficulty).add
            ((uint256(keccak256(abi.encodePacked(block.coinbase)))) / (now)).add
            (block.gaslimit).add
            ((uint256(keccak256(abi.encodePacked(msg.sender)))) / (now)).add
            (block.number)
            
        )));
        return uint24(randnum%1000000);
    }
}