/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleVotingEnd
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
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. An attacker must: 1) Wait for voting to be scheduled, 2) Monitor the blockchain for the approaching end time, 3) Execute transactions at specific times to manipulate the voting window. The vulnerability persists across multiple blocks and transactions, as the scheduled end time becomes part of the contract state that miners can manipulate within the ~15 minute window allowed by Ethereum consensus rules.
 */
pragma solidity ^0.4.18;

contract ForeignToken {
    function balanceOf(address _owner) public constant returns (uint256);
}

contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        newOwner = address(0);
    }
}

contract AMLOveCoinVoting is Owned {
    address private _tokenAddress;
    bool public votingAllowed = false;

    mapping (address => bool) yaVoto;
    uint256 public votosTotales;
    uint256 public donacionCruzRoja;
    uint256 public donacionTeleton;
    uint256 public inclusionEnExchange;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variable declarations need to be here, outside of constructor/function
    uint256 public votingEndTime;
    bool public votingScheduled = false;
    // === END VARIABLE DECLARATION ===

    function AMLOveCoinVoting(address tokenAddress) public {
        _tokenAddress = tokenAddress;
        votingAllowed = true;
    }

    function scheduleVotingEnd(uint256 _endTime) public onlyOwner {
        require(!votingScheduled);
        require(_endTime > now);
        votingEndTime = _endTime;
        votingScheduled = true;
    }

    function finalizeVotingResults() public {
        require(votingScheduled);
        require(now >= votingEndTime);
        require(votingAllowed);
        if (now <= votingEndTime + 300) {
            votingAllowed = false;
            emit VotingFinalized(votosTotales, donacionCruzRoja, donacionTeleton, inclusionEnExchange);
        }
    }

    function resetVotingSchedule() public onlyOwner {
        require(votingScheduled);
        require(!votingAllowed);
        votingScheduled = false;
        votingEndTime = 0;
    }

    event VotingFinalized(uint256 totalVotes, uint256 redCross, uint256 teleton, uint256 exchange);

    function enableVoting() onlyOwner public {
        votingAllowed = true;
    }

    function disableVoting() onlyOwner public {
        votingAllowed = false;
    }

    function vote(uint option) public {
        require(votingAllowed);
        require(option < 3);
        require(!yaVoto[msg.sender]);
        yaVoto[msg.sender] = true;
        ForeignToken token = ForeignToken(_tokenAddress);
        uint256 amount = token.balanceOf(msg.sender);
        require(amount > 0);
        votosTotales += amount;
        if (option == 0){
            donacionCruzRoja += amount;
        } else if (option == 1) {
            donacionTeleton += amount;
        } else if (option == 2) {
            inclusionEnExchange += amount;
        } else {
            assert(false);
        }        
    }

    function getStats() public view returns (
        uint256 _votosTotales,
        uint256 _donacionCruzRoja,
        uint256 _donacionTeleton,
        uint256 _inclusionEnExchange)
    {
        return (votosTotales, donacionCruzRoja, donacionTeleton, inclusionEnExchange);
    }
}
