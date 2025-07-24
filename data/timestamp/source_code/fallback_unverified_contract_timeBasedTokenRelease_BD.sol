/*
 * ===== SmartInject Injection Details =====
 * Function      : timeBasedTokenRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the token release mechanism relies on block.timestamp for time calculations. An attacker can exploit this by manipulating timestamps across multiple transactions: 1) First transaction: Call initializeTimeRelease() to start the release period, 2) Second transaction: Wait or manipulate timestamp, then call timeBasedTokenRelease() to claim tokens based on manipulated time, 3) Third transaction: Repeat the process to accumulate more tokens than intended. The vulnerability is stateful as it depends on the releaseActive state, lastReleaseTime, and requires multiple function calls to fully exploit.
 */
pragma solidity ^0.4.11;

contract Pi {
	uint256 public totalSupply;
	string public name;
	uint256 public decimals;
	string public symbol;
	address public owner;

	mapping (address => uint256) balances;
	mapping (address => mapping (address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variables to track time-based token release
    uint256 public releaseStartTime;
    uint256 public releaseEndTime;
    uint256 public tokensPerSecond;
    uint256 public lastReleaseTime;
    bool public releaseActive = false;
    
    // Initialize time-based token release
    function initializeTimeRelease(uint256 _duration, uint256 _tokensPerSecond) public {
        require(msg.sender == owner);
        require(!releaseActive);
        
        releaseStartTime = block.timestamp;
        releaseEndTime = block.timestamp + _duration;
        tokensPerSecond = _tokensPerSecond;
        lastReleaseTime = block.timestamp;
        releaseActive = true;
    }
    
    // Release tokens based on time elapsed - vulnerable to timestamp manipulation
    function timeBasedTokenRelease() public {
        require(releaseActive);
        require(block.timestamp >= releaseStartTime);
        require(block.timestamp <= releaseEndTime);
        
        uint256 timeElapsed = block.timestamp - lastReleaseTime;
        uint256 tokensToRelease = timeElapsed * tokensPerSecond;
        
        if (tokensToRelease > 0) {
            balances[msg.sender] += tokensToRelease;
            totalSupply += tokensToRelease;
            lastReleaseTime = block.timestamp;
        }
    }
    
    // Check if release period is over
    function isReleaseActive() public view returns (bool) {
        return releaseActive && block.timestamp <= releaseEndTime;
    }
    // === END FALLBACK INJECTION ===

    function Pi(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
        decimals = _decimalUnits;
        symbol = _symbol;
        name = _name;
        owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
    }

	//Fix for short address attack against ERC20
	modifier onlyPayloadSize(uint size) {
		assert(msg.data.length == size + 4);
		_;
	} 

	function balanceOf(address _owner) constant public returns (uint256) {
		return balances[_owner];
	}

	function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
		require(balances[msg.sender] >= _value && _value > 0);
	    balances[msg.sender] -= _value;
	    balances[_recipient] += _value;
	    Transfer(msg.sender, _recipient, _value);        
    }

	function transferFrom(address _from, address _to, uint256 _value) public {
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

	function approve(address _spender, uint256 _value) public {
		allowed[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
	}

	function allowance(address _owner, address _spender) constant public returns (uint256) {
		return allowed[_owner][_spender];
	}

	function mint(uint256 amount) public {
		assert(amount >= 0);
		require(msg.sender == owner);
		balances[msg.sender] += amount;
		totalSupply += amount;
	}

	//Event which is triggered to log all transfers to this contract's event log
	event Transfer(
		address indexed _from,
		address indexed _to,
		uint256 _value
		);
		
	//Event which is triggered whenever an owner approves a new allowance for a spender.
	event Approval(
		address indexed _owner,
		address indexed _spender,
		uint256 _value
		);

}
