FROM ruby:3.2-slim
RUN gem install webrick --no-doc
WORKDIR /app
COPY server.rb /app/server.rb
EXPOSE 3000
CMD ["ruby", "server.rb"]
