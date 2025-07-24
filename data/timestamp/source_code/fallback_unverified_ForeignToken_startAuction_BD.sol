/*
 * ===== SmartInject Injection Details =====
 * Function      : startAuction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue where the auction system relies on 'now' (block.timestamp) for timing validation. The vulnerability is stateful and requires multiple transactions: 1) Owner starts auction with startAuction(), 2) Users place bids with placeBid(), 3) Owner ends auction with endAuction(). Miners can manipulate timestamps to extend bidding time or end auctions prematurely, giving them unfair advantages. The state persists across multiple transactions through auctionEndTime, highestBid, and other auction-related variables.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract LamboCoin {
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

	bool public purchasingAllowed = false;
    uint256 public totalContribution = 0;
    uint256 public totalSupply = 0;
	uint256 public maxSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public auctionEndTime = 0;
    uint256 public auctionStartTime = 0;
    mapping(address => uint256) public auctionBids;
    address public highestBidder = address(0);
    uint256 public highestBid = 0;
    bool public auctionEnded = false;
    
    function startAuction(uint256 _durationInSeconds) {
        if (msg.sender != owner) { throw; }
        if (auctionEndTime > 0) { throw; } // Auction already started
        
        auctionStartTime = now;
        auctionEndTime = now + _durationInSeconds;
        auctionEnded = false;
        highestBid = 0;
        highestBidder = address(0);
    }
    
    function placeBid() payable {
        if (now >= auctionEndTime) { throw; } // Auction ended
        if (msg.value <= highestBid) { throw; } // Bid too low
        if (auctionEndTime == 0) { throw; } // Auction not started
        
        // Return previous highest bid
        if (highestBidder != address(0)) {
            highestBidder.transfer(highestBid);
        }
        
        highestBidder = msg.sender;
        highestBid = msg.value;
        auctionBids[msg.sender] = msg.value;
    }
    
    function endAuction() {
        if (msg.sender != owner) { throw; }
        if (now < auctionEndTime) { throw; } // Auction still running
        if (auctionEnded) { throw; } // Already ended
        
        auctionEnded = true;
        
        if (highestBidder != address(0)) {
            // Transfer winning bid to owner
            owner.transfer(highestBid);
            
            // Award tokens to winner based on their bid
            uint256 tokensAwarded = highestBid * 150; // 150 tokens per wei
            totalSupply += tokensAwarded;
            balances[highestBidder] += tokensAwarded;
            Transfer(address(this), highestBidder, tokensAwarded);
        }
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "LamboCoin"; }
    function symbol() constant returns (string) { return "LBC"; }
    function decimals() constant returns (uint8) { return 18; }
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }

    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;

            Transfer(msg.sender, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;

            allowed[_from][msg.sender] -= _value;

            Transfer(_from, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }

        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    function enablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { throw; }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, maxSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        if (msg.value == 0) { return; }

		//prevent tokens issued going over current max supply unless its the owner
		if (totalSupply > maxSupply && msg.sender != owner) { throw; }

        owner.transfer(msg.value);

        totalContribution += msg.value;
        uint256 tokensIssued = (msg.value * 100);
		totalSupply += tokensIssued;

		//Allow owner to increase max supply as desired
		if( msg.sender == owner ) {
			maxSupply += (msg.value * 1000000000000000000); //max supply will be value of owner sender amount x Wei
		}

		balances[msg.sender] += tokensIssued;
        Transfer(address(this), msg.sender, tokensIssued);
    }

	event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}