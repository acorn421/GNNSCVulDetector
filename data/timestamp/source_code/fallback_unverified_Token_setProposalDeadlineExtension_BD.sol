/*
 * ===== SmartInject Injection Details =====
 * Function      : setProposalDeadlineExtension
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 13 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that is stateful and requires multiple transactions to exploit. The vulnerability occurs because: 1) The function uses 'now' (block.timestamp) for deadline calculations which miners can manipulate within bounds, 2) It creates a race condition window where extensions can only be made within 10 minutes of the original deadline, 3) The state change (minExecutionDate modification) persists between transactions, 4) An attacker would need multiple transactions: first to create a proposal, then wait for the timing window, then call this function during the vulnerable window, and finally execute the proposal at an advantageous time. The vulnerability requires accumulated state changes and cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.16;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract tokenRecipient {
  event receivedEther(address sender, uint amount);
  event receivedTokens(address _from, uint256 _value, address _token, bytes _extraData);

  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public {
    Token t = Token(_token);
    require(t.transferFrom(_from, this, _value));
    receivedTokens(_from, _value, _token, _extraData);
  }

  function () payable public {
    receivedEther(msg.sender, msg.value);
  }
}

contract Token {
  mapping (address => uint256) public balanceOf;
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

/**
 * QWoodDAO contract
 */
contract QWoodDAO is Ownable, tokenRecipient {

  uint public minimumQuorum;
  uint public debatingPeriodInMinutes;
  Proposal[] public proposals;
  uint public numProposals;
  Token public sharesTokenAddress;
  uint256 public minShare;

  event ProposalAdded(uint proposalID, address recipient, uint amount, string description);
  event Voted(uint proposalID, bool position, address voter);
  event ProposalTallied(uint proposalID, uint result, uint quorum, bool active);
  event ChangeOfRules(uint newMinimumQuorum, uint newDebatingPeriodInMinutes, address newSharesTokenAddress, uint256 newMinShare);

  struct Vote {
    bool inSupport;
    address voter;
  }

  struct Proposal {
    address recipient;
    uint amount;
    string description;
    uint minExecutionDate;
    bool executed;
    bool proposalPassed;
    uint numberOfVotes;
    bytes32 proposalHash;
    Vote[] votes;
    mapping (address => bool) voted;
  }

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  /**
   * Set proposal deadline extension
   *
   * Allows emergency extension of proposal execution deadlines based on current timestamp
   * This is useful when network congestion or other issues prevent timely execution
   *
   * @param proposalNumber ID of the proposal to extend
   * @param extensionMinutes additional minutes to extend the deadline
   */
  function setProposalDeadlineExtension(uint proposalNumber, uint extensionMinutes) onlyOwner public {
    require(proposalNumber < proposals.length);
    Proposal storage p = proposals[proposalNumber];
    require(!p.executed);

    // Vulnerable: Using block.timestamp (now) for deadline calculation
    // Miners can manipulate timestamp within bounds to affect execution timing
    uint currentTime = now;

    // Only allow extension if current time is within 10 minutes of original deadline
    // This creates a race condition window that can be exploited across multiple transactions
    if (currentTime <= p.minExecutionDate + 10 minutes) {
      p.minExecutionDate = currentTime + extensionMinutes * 1 minutes;
    }
  }
  // === END FALLBACK INJECTION ===

  // Modifier that allows only shareholders to vote and create new proposals
  modifier onlyShareholders {
    require(sharesTokenAddress.balanceOf(msg.sender) > minShare);
    _;
  }

  /**
   * Constructor function
   *
   * First time setup
   */
  function QWoodDAO(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) payable public {
    changeVotingRules(sharesAddress, minimumSharesToPassAVote, minutesForDebate, minimumShare);
  }

  /**
   * Change voting rules
   *
   * Make so that proposals need to be discussed for at least `minutesForDebate/60` hours
   * and all voters combined must own more than `minimumSharesToPassAVote` shares of token `sharesAddress` to be executed
   *
   * @param sharesAddress token address
   * @param minimumSharesToPassAVote proposal can vote only if the sum of shares held by all voters exceed this number
   * @param minutesForDebate the minimum amount of delay between when a proposal is made and when it can be executed
   * @param minimumShare the minimum share of shareholders
   */
  function changeVotingRules(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) onlyOwner public {
    sharesTokenAddress = Token(sharesAddress);
    if (minimumSharesToPassAVote == 0 ) minimumSharesToPassAVote = 1;
    minimumQuorum = minimumSharesToPassAVote;
    debatingPeriodInMinutes = minutesForDebate;
    minShare = minimumShare;
    ChangeOfRules(minimumQuorum, debatingPeriodInMinutes, sharesTokenAddress, minShare);
  }

  /**
   * Add Proposal
   *
   * Propose to send `weiAmount / 1e18` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   *
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send, in wei
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposal(
    address beneficiary,
    uint weiAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    proposalID = proposals.length++;
    Proposal storage p = proposals[proposalID];
    p.recipient = beneficiary;
    p.amount = weiAmount;
    p.description = jobDescription;
    p.proposalHash = keccak256(beneficiary, weiAmount, transactionBytecode);
    p.minExecutionDate = now + debatingPeriodInMinutes * 1 minutes;
    p.executed = false;
    p.proposalPassed = false;
    p.numberOfVotes = 0;
    ProposalAdded(proposalID, beneficiary, weiAmount, jobDescription);
    numProposals = proposalID+1;

    return proposalID;
  }

  /**
   * Add proposal in Ether
   *
   * Propose to send `etherAmount` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   * This is a convenience function to use if the amount to be given is in round number of ether units.
   *
   * @param beneficiary who to send the ether to
   * @param etherAmount amount of ether to send
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposalInEther(
    address beneficiary,
    uint etherAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    return newProposal(beneficiary, etherAmount * 1 ether, jobDescription, transactionBytecode);
  }

  /**
   * Check if a proposal code matches
   *
   * @param proposalNumber ID number of the proposal to query
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send
   * @param transactionBytecode bytecode of transaction
   */
  function checkProposalCode(
    uint proposalNumber,
    address beneficiary,
    uint weiAmount,
    bytes transactionBytecode
  )
  constant public
  returns (bool codeChecksOut)
  {
    Proposal storage p = proposals[proposalNumber];
    return p.proposalHash == keccak256(beneficiary, weiAmount, transactionBytecode);
  }

  /**
   * Log a vote for a proposal
   *
   * Vote `supportsProposal? in support of : against` proposal #`proposalNumber`
   *
   * @param proposalNumber number of proposal
   * @param supportsProposal either in favor or against it
   */
  function vote(
    uint proposalNumber,
    bool supportsProposal
  )
  onlyShareholders public
  returns (uint voteID)
  {
    Proposal storage p = proposals[proposalNumber];
    require(p.voted[msg.sender] != true);

    voteID = p.votes.length++;
    p.votes[voteID] = Vote({inSupport: supportsProposal, voter: msg.sender});
    p.voted[msg.sender] = true;
    p.numberOfVotes = voteID +1;
    Voted(proposalNumber,  supportsProposal, msg.sender);
    return voteID;
  }

  /**
   * Finish vote
   *
   * Count the votes proposal #`proposalNumber` and execute it if approved
   *
   * @param proposalNumber proposal number
   * @param transactionBytecode optional: if the transaction contained a bytecode, you need to send it
   */
  function executeProposal(uint proposalNumber, bytes transactionBytecode) public {
    Proposal storage p = proposals[proposalNumber];

    require(now > p.minExecutionDate                                             // If it is past the voting deadline
    && !p.executed                                                          // and it has not already been executed
    && p.proposalHash == keccak256(p.recipient, p.amount, transactionBytecode)); // and the supplied code matches the proposal...


    // ...then tally the results
    uint quorum = 0;
    uint yea = 0;
    uint nay = 0;

    for (uint i = 0; i <  p.votes.length; ++i) {
      Vote storage v = p.votes[i];
      uint voteWeight = sharesTokenAddress.balanceOf(v.voter);
      quorum += voteWeight;
      if (v.inSupport) {
        yea += voteWeight;
      } else {
        nay += voteWeight;
      }
    }

    require(quorum >= minimumQuorum); // Check if a minimum quorum has been reached

    if (yea > nay ) {
      // Proposal passed; execute the transaction

      p.executed = true;
      require(p.recipient.call.value(p.amount)(transactionBytecode));

      p.proposalPassed = true;
    } else {
      // Proposal failed
      p.proposalPassed = false;
    }

    // Fire Events
    ProposalTallied(proposalNumber, yea - nay, quorum, p.proposalPassed);
  }
}
