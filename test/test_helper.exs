# The AWS Encryption SDK decrypt vectors are excluded unless asked for
# (`mix test --only aws_vectors`, as CI's aws-vectors job runs them): their
# corpus is fetched, never committed. Encryptor.AwsVectors says how.
unless Encryptor.AwsVectors.present?() do
  IO.puts("aws_vectors corpus absent: " <> Encryptor.AwsVectors.absent_message())
end

ExUnit.start(exclude: [:aws_vectors])
